// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Playback_H
#define WINRT_Windows_Media_Playback_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Audio.2.h"
#include "winrt/impl/Windows.Media.Casting.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Protection.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayer) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::Current() const
    {
        void* player{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->get_Current(&player));
        return winrt::Windows::Media::Playback::MediaPlayer{ player, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->add_MessageReceivedFromBackground(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground_revoker consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MessageReceivedFromBackground_revoker>(this, MessageReceivedFromBackground(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->remove_MessageReceivedFromBackground(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground(winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->add_MessageReceivedFromForeground(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground_revoker consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MessageReceivedFromForeground_revoker>(this, MessageReceivedFromForeground(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->remove_MessageReceivedFromForeground(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::SendMessageToBackground(winrt::Windows::Foundation::Collections::ValueSet const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->SendMessageToBackground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::SendMessageToForeground(winrt::Windows::Foundation::Collections::ValueSet const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->SendMessageToForeground(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::IsMediaPlaying() const
    {
        bool isMediaPlaying{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->IsMediaPlaying(&isMediaPlaying));
        return isMediaPlaying;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::Shutdown() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics)->Shutdown());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs<D>::NewItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs)->get_NewItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs<D>::OldItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs)->get_OldItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItemChangedReason) consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs2<D>::Reason() const
    {
        winrt::Windows::Media::Playback::MediaPlaybackItemChangedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackList) consume_Windows_Media_Playback_IMediaBreak<D>::PlaybackList() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreak)->get_PlaybackList(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackList{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Playback_IMediaBreak<D>::PresentationPosition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreak)->get_PresentationPosition(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreakInsertionMethod) consume_Windows_Media_Playback_IMediaBreak<D>::InsertionMethod() const
    {
        winrt::Windows::Media::Playback::MediaBreakInsertionMethod value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreak)->get_InsertionMethod(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Media_Playback_IMediaBreak<D>::CustomProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreak)->get_CustomProperties(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaBreak<D>::CanStart() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreak)->get_CanStart(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreak<D>::CanStart(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreak)->put_CanStart(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakEndedEventArgs<D>::MediaBreak() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakEndedEventArgs)->get_MediaBreak(&value));
        return winrt::Windows::Media::Playback::MediaBreak{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakFactory<D>::Create(winrt::Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakFactory)->Create(static_cast<int32_t>(insertionMethod), &result));
        return winrt::Windows::Media::Playback::MediaBreak{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakFactory<D>::CreateWithPresentationPosition(winrt::Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod, winrt::Windows::Foundation::TimeSpan const& presentationPosition) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakFactory)->CreateWithPresentationPosition(static_cast<int32_t>(insertionMethod), impl::bind_in(presentationPosition), &result));
        return winrt::Windows::Media::Playback::MediaBreak{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->add_BreaksSeekedOver(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, BreaksSeekedOver_revoker>(this, BreaksSeekedOver(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->remove_BreaksSeekedOver(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakStartedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->add_BreakStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, BreakStarted_revoker>(this, BreakStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->remove_BreakStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakEndedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->add_BreakEnded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakEndedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, BreakEnded_revoker>(this, BreakEnded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->remove_BreakEnded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakSkippedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->add_BreakSkipped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakSkippedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, BreakSkipped_revoker>(this, BreakSkipped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->remove_BreakSkipped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakManager<D>::CurrentBreak() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->get_CurrentBreak(&value));
        return winrt::Windows::Media::Playback::MediaBreak{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackSession) consume_Windows_Media_Playback_IMediaBreakManager<D>::PlaybackSession() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->get_PlaybackSession(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakManager<D>::PlayBreak(winrt::Windows::Media::Playback::MediaBreak const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->PlayBreak(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakManager<D>::SkipCurrentBreak() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakManager)->SkipCurrentBreak());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakSchedule, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->add_ScheduleChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged_revoker consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakSchedule, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ScheduleChanged_revoker>(this, ScheduleChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->remove_ScheduleChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::InsertMidrollBreak(winrt::Windows::Media::Playback::MediaBreak const& mediaBreak) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->InsertMidrollBreak(*(void**)(&mediaBreak)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::RemoveMidrollBreak(winrt::Windows::Media::Playback::MediaBreak const& mediaBreak) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->RemoveMidrollBreak(*(void**)(&mediaBreak)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaBreak>) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::MidrollBreaks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->get_MidrollBreaks(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaBreak>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PrerollBreak(winrt::Windows::Media::Playback::MediaBreak const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->put_PrerollBreak(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PrerollBreak() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->get_PrerollBreak(&value));
        return winrt::Windows::Media::Playback::MediaBreak{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PostrollBreak(winrt::Windows::Media::Playback::MediaBreak const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->put_PostrollBreak(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PostrollBreak() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->get_PostrollBreak(&value));
        return winrt::Windows::Media::Playback::MediaBreak{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PlaybackItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSchedule)->get_PlaybackItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaBreak>) consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs<D>::SeekedOverBreaks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs)->get_SeekedOverBreaks(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaBreak>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs<D>::OldPosition() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs)->get_OldPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs<D>::NewPosition() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs)->get_NewPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakSkippedEventArgs<D>::MediaBreak() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakSkippedEventArgs)->get_MediaBreak(&value));
        return winrt::Windows::Media::Playback::MediaBreak{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreak) consume_Windows_Media_Playback_IMediaBreakStartedEventArgs<D>::MediaBreak() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaBreakStartedEventArgs)->get_MediaBreak(&value));
        return winrt::Windows::Media::Playback::MediaBreak{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaEnginePlaybackSource<D>::CurrentItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaEnginePlaybackSource)->get_CurrentItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaEnginePlaybackSource<D>::SetPlaybackSource(winrt::Windows::Media::Playback::IMediaPlaybackSource const& source) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaEnginePlaybackSource)->SetPlaybackSource(*(void**)(&source)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaPlaybackType) consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Type() const
    {
        winrt::Windows::Media::MediaPlaybackType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaItemDisplayProperties)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Type(winrt::Windows::Media::MediaPlaybackType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaItemDisplayProperties)->put_Type(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MusicDisplayProperties) consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::MusicProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaItemDisplayProperties)->get_MusicProperties(&value));
        return winrt::Windows::Media::MusicDisplayProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoDisplayProperties) consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::VideoProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaItemDisplayProperties)->get_VideoProperties(&value));
        return winrt::Windows::Media::VideoDisplayProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaItemDisplayProperties)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Thumbnail(winrt::Windows::Storage::Streams::RandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaItemDisplayProperties)->put_Thumbnail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::ClearAll() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaItemDisplayProperties)->ClearAll());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayer) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::MediaPlayer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_MediaPlayer(&value));
        return winrt::Windows::Media::Playback::MediaPlayer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PlayBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PauseBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_NextBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PreviousBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_FastForwardBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_RewindBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_ShuffleBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_AutoRepeatModeBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PositionBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateBehavior() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->get_RateBehavior(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PlayReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PlayReceived_revoker>(this, PlayReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PlayReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PauseReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PauseReceived_revoker>(this, PauseReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PauseReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_NextReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NextReceived_revoker>(this, NextReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_NextReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PreviousReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PreviousReceived_revoker>(this, PreviousReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PreviousReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_FastForwardReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FastForwardReceived_revoker>(this, FastForwardReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_FastForwardReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_RewindReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RewindReceived_revoker>(this, RewindReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_RewindReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_ShuffleReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ShuffleReceived_revoker>(this, ShuffleReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_ShuffleReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_AutoRepeatModeReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AutoRepeatModeReceived_revoker>(this, AutoRepeatModeReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_AutoRepeatModeReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PositionReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PositionReceived_revoker>(this, PositionReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PositionReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->add_RateReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RateReceived_revoker>(this, RateReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_RateReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaPlaybackAutoRepeatMode) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::AutoRepeatMode() const
    {
        winrt::Windows::Media::MediaPlaybackAutoRepeatMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->get_AutoRepeatMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManager) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::CommandManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->get_CommandManager(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaCommandEnablingRule) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::EnablingRule() const
    {
        winrt::Windows::Media::Playback::MediaCommandEnablingRule value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->get_EnablingRule(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::EnablingRule(winrt::Windows::Media::Playback::MediaCommandEnablingRule const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->put_EnablingRule(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->add_IsEnabledChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsEnabledChanged_revoker>(this, IsEnabledChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->remove_IsEnabledChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::PlaybackRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->get_PlaybackRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::IsShuffleRequested() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->get_IsShuffleRequested(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->GetDeferral(&value));
        return winrt::Windows::Foundation::Deferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->add_AudioTracksChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AudioTracksChanged_revoker>(this, AudioTracksChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->remove_AudioTracksChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->add_VideoTracksChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, VideoTracksChanged_revoker>(this, VideoTracksChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->remove_VideoTracksChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->add_TimedMetadataTracksChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TimedMetadataTracksChanged_revoker>(this, TimedMetadataTracksChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->remove_TimedMetadataTracksChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->get_Source(&value));
        return winrt::Windows::Media::Core::MediaSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackAudioTrackList) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->get_AudioTracks(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackAudioTrackList{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackVideoTrackList) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->get_VideoTracks(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackVideoTrackList{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList) consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem)->get_TimedMetadataTracks(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreakSchedule) consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::BreakSchedule() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem2)->get_BreakSchedule(&value));
        return winrt::Windows::Media::Playback::MediaBreakSchedule{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::StartTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem2)->get_StartTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::DurationLimit() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem2)->get_DurationLimit(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::CanSkip() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem2)->get_CanSkip(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::CanSkip(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem2)->put_CanSkip(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaItemDisplayProperties) consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::GetDisplayProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem2)->GetDisplayProperties(&value));
        return winrt::Windows::Media::Playback::MediaItemDisplayProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::ApplyDisplayProperties(winrt::Windows::Media::Playback::MediaItemDisplayProperties const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem2)->ApplyDisplayProperties(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::IsDisabledInPlaybackList() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem3)->get_IsDisabledInPlaybackList(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::IsDisabledInPlaybackList(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem3)->put_IsDisabledInPlaybackList(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::TotalDownloadProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem3)->get_TotalDownloadProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::AutoLoadedDisplayPropertyKind) consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::AutoLoadedDisplayProperties() const
    {
        winrt::Windows::Media::Playback::AutoLoadedDisplayPropertyKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem3)->get_AutoLoadedDisplayProperties(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::AutoLoadedDisplayProperties(winrt::Windows::Media::Playback::AutoLoadedDisplayPropertyKind const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItem3)->put_AutoLoadedDisplayProperties(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItemErrorCode) consume_Windows_Media_Playback_IMediaPlaybackItemError<D>::ErrorCode() const
    {
        winrt::Windows::Media::Playback::MediaPlaybackItemErrorCode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemError)->get_ErrorCode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Playback_IMediaPlaybackItemError<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemError)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackItemFactory<D>::Create(winrt::Windows::Media::Core::MediaSource const& source) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemFactory)->Create(*(void**)(&source), &value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackItemFactory2<D>::CreateWithStartTime(winrt::Windows::Media::Core::MediaSource const& source, winrt::Windows::Foundation::TimeSpan const& startTime) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemFactory2)->CreateWithStartTime(*(void**)(&source), impl::bind_in(startTime), &result));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackItemFactory2<D>::CreateWithStartTimeAndDurationLimit(winrt::Windows::Media::Core::MediaSource const& source, winrt::Windows::Foundation::TimeSpan const& startTime, winrt::Windows::Foundation::TimeSpan const& durationLimit) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemFactory2)->CreateWithStartTimeAndDurationLimit(*(void**)(&source), impl::bind_in(startTime), impl::bind_in(durationLimit), &result));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackItemFailedEventArgs<D>::Item() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs)->get_Item(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItemError) consume_Windows_Media_Playback_IMediaPlaybackItemFailedEventArgs<D>::Error() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs)->get_Error(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItemError{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackItemOpenedEventArgs<D>::Item() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs)->get_Item(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackItemStatics<D>::FindFromMediaSource(winrt::Windows::Media::Core::MediaSource const& source) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackItemStatics)->FindFromMediaSource(*(void**)(&source), &value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->add_ItemFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed_revoker consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ItemFailed_revoker>(this, ItemFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->remove_ItemFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->add_CurrentItemChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CurrentItemChanged_revoker>(this, CurrentItemChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->remove_CurrentItemChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->add_ItemOpened(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened_revoker consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ItemOpened_revoker>(this, ItemOpened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->remove_ItemOpened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Playback::MediaPlaybackItem>) consume_Windows_Media_Playback_IMediaPlaybackList<D>::Items() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->get_Items(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Playback::MediaPlaybackItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackList<D>::AutoRepeatEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->get_AutoRepeatEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList<D>::AutoRepeatEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->put_AutoRepeatEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackList<D>::ShuffleEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->get_ShuffleEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList<D>::ShuffleEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->put_ShuffleEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->get_CurrentItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemIndex() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->get_CurrentItemIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackList<D>::MoveNext() const
    {
        void* item{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->MoveNext(&item));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ item, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackList<D>::MovePrevious() const
    {
        void* item{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->MovePrevious(&item));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ item, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackList<D>::MoveTo(uint32_t itemIndex) const
    {
        void* item{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList)->MoveTo(itemIndex, &item));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ item, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Playback_IMediaPlaybackList2<D>::MaxPrefetchTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList2)->get_MaxPrefetchTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList2<D>::MaxPrefetchTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList2)->put_MaxPrefetchTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Playback_IMediaPlaybackList2<D>::StartingItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList2)->get_StartingItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList2<D>::StartingItem(winrt::Windows::Media::Playback::MediaPlaybackItem const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList2)->put_StartingItem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaPlaybackItem>) consume_Windows_Media_Playback_IMediaPlaybackList2<D>::ShuffledItems() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList2)->get_ShuffledItems(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaPlaybackItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList2<D>::SetShuffledItems(param::iterable<winrt::Windows::Media::Playback::MediaPlaybackItem> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList2)->SetShuffledItems(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Playback_IMediaPlaybackList3<D>::MaxPlayedItemsToKeepOpen() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList3)->get_MaxPlayedItemsToKeepOpen(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackList3<D>::MaxPlayedItemsToKeepOpen(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackList3)->put_MaxPlayedItemsToKeepOpen(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_PlaybackStateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, PlaybackStateChanged_revoker>(this, PlaybackStateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_PlaybackStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_PlaybackRateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, PlaybackRateChanged_revoker>(this, PlaybackRateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_PlaybackRateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_SeekCompleted(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, SeekCompleted_revoker>(this, SeekCompleted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_SeekCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_BufferingStarted(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, BufferingStarted_revoker>(this, BufferingStarted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_BufferingStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_BufferingEnded(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, BufferingEnded_revoker>(this, BufferingEnded(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_BufferingEnded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_BufferingProgressChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, BufferingProgressChanged_revoker>(this, BufferingProgressChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_BufferingProgressChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_DownloadProgressChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, DownloadProgressChanged_revoker>(this, DownloadProgressChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_DownloadProgressChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_NaturalDurationChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, NaturalDurationChanged_revoker>(this, NaturalDurationChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_NaturalDurationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_PositionChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, PositionChanged_revoker>(this, PositionChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_PositionChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->add_NaturalVideoSizeChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, NaturalVideoSizeChanged_revoker>(this, NaturalVideoSizeChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->remove_NaturalVideoSizeChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayer) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::MediaPlayer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_MediaPlayer(&value));
        return winrt::Windows::Media::Playback::MediaPlayer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_NaturalDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::Position(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackState) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackState() const
    {
        winrt::Windows::Media::Playback::MediaPlaybackState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_PlaybackState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::CanSeek() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_CanSeek(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::CanPause() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_CanPause(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::IsProtected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_IsProtected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_PlaybackRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRate(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->put_PlaybackRate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_BufferingProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_DownloadProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoHeight() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_NaturalVideoHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoWidth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_NaturalVideoWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NormalizedSourceRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_NormalizedSourceRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NormalizedSourceRect(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->put_NormalizedSourceRect(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::StereoscopicVideoPackingMode() const
    {
        winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->get_StereoscopicVideoPackingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession<D>::StereoscopicVideoPackingMode(winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession)->put_StereoscopicVideoPackingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->add_BufferedRangesChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, BufferedRangesChanged_revoker>(this, BufferedRangesChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->remove_BufferedRangesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->add_PlayedRangesChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, PlayedRangesChanged_revoker>(this, PlayedRangesChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->remove_PlayedRangesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->add_SeekableRangesChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, SeekableRangesChanged_revoker>(this, SeekableRangesChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->remove_SeekableRangesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->add_SupportedPlaybackRatesChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, SupportedPlaybackRatesChanged_revoker>(this, SupportedPlaybackRatesChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->remove_SupportedPlaybackRatesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackSphericalVideoProjection) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SphericalVideoProjection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->get_SphericalVideoProjection(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackSphericalVideoProjection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::IsMirroring() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->get_IsMirroring(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::IsMirroring(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->put_IsMirroring(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::GetBufferedRanges() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->GetBufferedRanges(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::GetPlayedRanges() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->GetPlayedRanges(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::GetSeekableRanges() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->GetSeekableRanges(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::IsSupportedPlaybackRateRange(double rate1, double rate2) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession2)->IsSupportedPlaybackRateRange(rate1, rate2, &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaRotation) consume_Windows_Media_Playback_IMediaPlaybackSession3<D>::PlaybackRotation() const
    {
        winrt::Windows::Media::MediaProperties::MediaRotation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession3)->get_PlaybackRotation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSession3<D>::PlaybackRotation(winrt::Windows::Media::MediaProperties::MediaRotation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession3)->put_PlaybackRotation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState) consume_Windows_Media_Playback_IMediaPlaybackSession3<D>::GetOutputDegradationPolicyState() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSession3)->GetOutputDegradationPolicyState(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackSessionBufferingStartedEventArgs<D>::IsPlaybackInterruption() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs)->get_IsPlaybackInterruption(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason) consume_Windows_Media_Playback_IMediaPlaybackSessionOutputDegradationPolicyState<D>::VideoConstrictionReason() const
    {
        winrt::Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState)->get_VideoConstrictionReason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::FrameFormat() const
    {
        winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_FrameFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::FrameFormat(winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_FrameFormat(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::HorizontalFieldOfViewInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_HorizontalFieldOfViewInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::HorizontalFieldOfViewInDegrees(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_HorizontalFieldOfViewInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ViewOrientation() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_ViewOrientation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ViewOrientation(winrt::Windows::Foundation::Numerics::quaternion const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_ViewOrientation(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::SphericalVideoProjectionMode) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ProjectionMode() const
    {
        winrt::Windows::Media::Playback::SphericalVideoProjectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_ProjectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ProjectionMode(winrt::Windows::Media::Playback::SphericalVideoProjectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_ProjectionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, winrt::Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->add_PresentationModeChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, winrt::Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PresentationModeChanged_revoker>(this, PresentationModeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->remove_PresentationModeChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode) consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::GetPresentationMode(uint32_t index) const
    {
        winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->GetPresentationMode(index, reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::SetPresentationMode(uint32_t index, winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->SetPresentationMode(index, static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer<D>::AutoPlay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_AutoPlay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::AutoPlay(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->put_AutoPlay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaPlayer<D>::NaturalDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_NaturalDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaPlayer<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::Position(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_BufferingProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayerState) consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentState() const
    {
        winrt::Windows::Media::Playback::MediaPlayerState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_CurrentState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer<D>::CanSeek() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_CanSeek(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer<D>::CanPause() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_CanPause(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer<D>::IsLoopingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_IsLoopingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::IsLoopingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->put_IsLoopingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer<D>::IsProtected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_IsProtected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer<D>::IsMuted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_IsMuted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::IsMuted(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->put_IsMuted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_PlaybackRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackRate(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->put_PlaybackRate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlayer<D>::Volume() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_Volume(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::Volume(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->put_Volume(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::PlaybackMediaMarkerSequence) consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->get_PlaybackMediaMarkers(&value));
        return winrt::Windows::Media::Playback::PlaybackMediaMarkerSequence{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_MediaOpened(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, MediaOpened_revoker>(this, MediaOpened(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_MediaOpened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_MediaEnded(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, MediaEnded_revoker>(this, MediaEnded(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_MediaEnded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::MediaPlayerFailedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_MediaFailed(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::MediaPlayerFailedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MediaFailed_revoker>(this, MediaFailed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_MediaFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_CurrentStateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, CurrentStateChanged_revoker>(this, CurrentStateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_CurrentStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_PlaybackMediaMarkerReached(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, PlaybackMediaMarkerReached_revoker>(this, PlaybackMediaMarkerReached(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_PlaybackMediaMarkerReached(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_MediaPlayerRateChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, MediaPlayerRateChanged_revoker>(this, MediaPlayerRateChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_MediaPlayerRateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_VolumeChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, VolumeChanged_revoker>(this, VolumeChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_VolumeChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_SeekCompleted(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, SeekCompleted_revoker>(this, SeekCompleted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_SeekCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_BufferingStarted(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, BufferingStarted_revoker>(this, BufferingStarted(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_BufferingStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->add_BufferingEnded(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, BufferingEnded_revoker>(this, BufferingEnded(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->remove_BufferingEnded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::Play() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->Play());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer<D>::SetUriSource(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer)->SetUriSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SystemMediaTransportControls) consume_Windows_Media_Playback_IMediaPlayer2<D>::SystemMediaTransportControls() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer2)->get_SystemMediaTransportControls(&value));
        return winrt::Windows::Media::SystemMediaTransportControls{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayerAudioCategory) consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioCategory() const
    {
        winrt::Windows::Media::Playback::MediaPlayerAudioCategory value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer2)->get_AudioCategory(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioCategory(winrt::Windows::Media::Playback::MediaPlayerAudioCategory const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer2)->put_AudioCategory(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayerAudioDeviceType) consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioDeviceType() const
    {
        winrt::Windows::Media::Playback::MediaPlayerAudioDeviceType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer2)->get_AudioDeviceType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioDeviceType(winrt::Windows::Media::Playback::MediaPlayerAudioDeviceType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer2)->put_AudioDeviceType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->add_IsMutedChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged_revoker consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, IsMutedChanged_revoker>(this, IsMutedChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->remove_IsMutedChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->add_SourceChanged(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged_revoker consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, SourceChanged_revoker>(this, SourceChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->remove_SourceChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioBalance() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_AudioBalance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioBalance(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->put_AudioBalance(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer3<D>::RealTimePlayback() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_RealTimePlayback(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::RealTimePlayback(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->put_RealTimePlayback(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::StereoscopicVideoRenderMode) consume_Windows_Media_Playback_IMediaPlayer3<D>::StereoscopicVideoRenderMode() const
    {
        winrt::Windows::Media::Playback::StereoscopicVideoRenderMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_StereoscopicVideoRenderMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::StereoscopicVideoRenderMode(winrt::Windows::Media::Playback::StereoscopicVideoRenderMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->put_StereoscopicVideoRenderMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaBreakManager) consume_Windows_Media_Playback_IMediaPlayer3<D>::BreakManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_BreakManager(&value));
        return winrt::Windows::Media::Playback::MediaBreakManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackCommandManager) consume_Windows_Media_Playback_IMediaPlayer3<D>::CommandManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_CommandManager(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackCommandManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_AudioDevice(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioDevice(winrt::Windows::Devices::Enumeration::DeviceInformation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->put_AudioDevice(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaTimelineController) consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_TimelineController(&value));
        return winrt::Windows::Media::MediaTimelineController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineController(winrt::Windows::Media::MediaTimelineController const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->put_TimelineController(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineControllerPositionOffset() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_TimelineControllerPositionOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineControllerPositionOffset(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->put_TimelineControllerPositionOffset(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackSession) consume_Windows_Media_Playback_IMediaPlayer3<D>::PlaybackSession() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->get_PlaybackSession(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::StepForwardOneFrame() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->StepForwardOneFrame());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer3<D>::StepBackwardOneFrame() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->StepBackwardOneFrame());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Casting::CastingSource) consume_Windows_Media_Playback_IMediaPlayer3<D>::GetAsCastingSource() const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer3)->GetAsCastingSource(&returnValue));
        return winrt::Windows::Media::Casting::CastingSource{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer4<D>::SetSurfaceSize(winrt::Windows::Foundation::Size const& size) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer4)->SetSurfaceSize(impl::bind_in(size)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayerSurface) consume_Windows_Media_Playback_IMediaPlayer4<D>::GetSurface(winrt::Windows::UI::Composition::Compositor const& compositor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer4)->GetSurface(*(void**)(&compositor), &result));
        return winrt::Windows::Media::Playback::MediaPlayerSurface{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer5)->add_VideoFrameAvailable(*(void**)(&value), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable_revoker consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& value) const
    {
        return impl::make_event_revoker<D, VideoFrameAvailable_revoker>(this, VideoFrameAvailable(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer5)->remove_VideoFrameAvailable(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer5<D>::IsVideoFrameServerEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer5)->get_IsVideoFrameServerEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer5<D>::IsVideoFrameServerEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer5)->put_IsVideoFrameServerEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer5<D>::CopyFrameToVideoSurface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer5)->CopyFrameToVideoSurface(*(void**)(&destination)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer5<D>::CopyFrameToVideoSurface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination, winrt::Windows::Foundation::Rect const& targetRectangle) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer5)->CopyFrameToVideoSurfaceWithTargetRectangle(*(void**)(&destination), impl::bind_in(targetRectangle)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer5<D>::CopyFrameToStereoscopicVideoSurfaces(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destinationLeftEye, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destinationRightEye) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer5)->CopyFrameToStereoscopicVideoSurfaces(*(void**)(&destinationLeftEye), *(void**)(&destinationRightEye)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer6)->add_SubtitleFrameChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged_revoker consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SubtitleFrameChanged_revoker>(this, SubtitleFrameChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer6)->remove_SubtitleFrameChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer6<D>::RenderSubtitlesToSurface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer6)->RenderSubtitlesToSurface(*(void**)(&destination), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Playback_IMediaPlayer6<D>::RenderSubtitlesToSurface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination, winrt::Windows::Foundation::Rect const& targetRectangle) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer6)->RenderSubtitlesToSurfaceWithTargetRectangle(*(void**)(&destination), impl::bind_in(targetRectangle), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Playback_IMediaPlayer7<D>::AudioStateMonitor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayer7)->get_AudioStateMonitor(&value));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Media_Playback_IMediaPlayerDataReceivedEventArgs<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs)->get_Data(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerEffects<D>::AddAudioEffect(param::hstring const& activatableClassId, bool effectOptional, winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerEffects)->AddAudioEffect(*(void**)(&activatableClassId), effectOptional, *(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerEffects<D>::RemoveAllEffects() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerEffects)->RemoveAllEffects());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerEffects2<D>::AddVideoEffect(param::hstring const& activatableClassId, bool effectOptional, winrt::Windows::Foundation::Collections::IPropertySet const& effectConfiguration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerEffects2)->AddVideoEffect(*(void**)(&activatableClassId), effectOptional, *(void**)(&effectConfiguration)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayerError) consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs<D>::Error() const
    {
        winrt::Windows::Media::Playback::MediaPlayerError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs)->get_Error(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs<D>::ExtendedErrorCode() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs)->get_ExtendedErrorCode(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs<D>::ErrorMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs)->get_ErrorMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Playback_IMediaPlayerRateChangedEventArgs<D>::NewRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerRateChangedEventArgs)->get_NewRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::MediaProtectionManager) consume_Windows_Media_Playback_IMediaPlayerSource<D>::ProtectionManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSource)->get_ProtectionManager(&value));
        return winrt::Windows::Media::Protection::MediaProtectionManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerSource<D>::ProtectionManager(winrt::Windows::Media::Protection::MediaProtectionManager const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSource)->put_ProtectionManager(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerSource<D>::SetFileSource(winrt::Windows::Storage::IStorageFile const& file) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSource)->SetFileSource(*(void**)(&file)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerSource<D>::SetStreamSource(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSource)->SetStreamSource(*(void**)(&stream)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerSource<D>::SetMediaSource(winrt::Windows::Media::Core::IMediaSource const& source) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSource)->SetMediaSource(*(void**)(&source)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::IMediaPlaybackSource) consume_Windows_Media_Playback_IMediaPlayerSource2<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSource2)->get_Source(&value));
        return winrt::Windows::Media::Playback::IMediaPlaybackSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IMediaPlayerSource2<D>::Source(winrt::Windows::Media::Playback::IMediaPlaybackSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSource2)->put_Source(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ICompositionSurface) consume_Windows_Media_Playback_IMediaPlayerSurface<D>::CompositionSurface() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSurface)->get_CompositionSurface(&value));
        return winrt::Windows::UI::Composition::ICompositionSurface{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Compositor) consume_Windows_Media_Playback_IMediaPlayerSurface<D>::Compositor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSurface)->get_Compositor(&value));
        return winrt::Windows::UI::Composition::Compositor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlayer) consume_Windows_Media_Playback_IMediaPlayerSurface<D>::MediaPlayer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IMediaPlayerSurface)->get_MediaPlayer(&value));
        return winrt::Windows::Media::Playback::MediaPlayer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Playback_IPlaybackMediaMarker<D>::Time() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarker)->get_Time(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Playback_IPlaybackMediaMarker<D>::MediaMarkerType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarker)->get_MediaMarkerType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Playback_IPlaybackMediaMarker<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarker)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::PlaybackMediaMarker) consume_Windows_Media_Playback_IPlaybackMediaMarkerFactory<D>::CreateFromTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        void* marker{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarkerFactory)->CreateFromTime(impl::bind_in(value), &marker));
        return winrt::Windows::Media::Playback::PlaybackMediaMarker{ marker, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::PlaybackMediaMarker) consume_Windows_Media_Playback_IPlaybackMediaMarkerFactory<D>::Create(winrt::Windows::Foundation::TimeSpan const& value, param::hstring const& mediaMarketType, param::hstring const& text) const
    {
        void* marker{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarkerFactory)->Create(impl::bind_in(value), *(void**)(&mediaMarketType), *(void**)(&text), &marker));
        return winrt::Windows::Media::Playback::PlaybackMediaMarker{ marker, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::PlaybackMediaMarker) consume_Windows_Media_Playback_IPlaybackMediaMarkerReachedEventArgs<D>::PlaybackMediaMarker() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs)->get_PlaybackMediaMarker(&value));
        return winrt::Windows::Media::Playback::PlaybackMediaMarker{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence<D>::Size() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence)->get_Size(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence<D>::Insert(winrt::Windows::Media::Playback::PlaybackMediaMarker const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence)->Insert(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataTrack) consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs<D>::Track() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs)->get_Track(&value));
        return winrt::Windows::Media::Core::TimedMetadataTrack{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode) consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs<D>::OldPresentationMode() const
    {
        winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs)->get_OldPresentationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode) consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs<D>::NewPresentationMode() const
    {
        winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs)->get_NewPresentationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics> : produce_base<D, winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics>
    {
        int32_t __stdcall get_Current(void** player) noexcept final try
        {
            clear_abi(player);
            typename D::abi_guard guard(this->shim());
            *player = detach_from<winrt::Windows::Media::Playback::MediaPlayer>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MessageReceivedFromBackground(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MessageReceivedFromBackground(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageReceivedFromBackground(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageReceivedFromBackground(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MessageReceivedFromForeground(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MessageReceivedFromForeground(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageReceivedFromForeground(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageReceivedFromForeground(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall SendMessageToBackground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendMessageToBackground(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendMessageToForeground(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendMessageToForeground(*reinterpret_cast<winrt::Windows::Foundation::Collections::ValueSet const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsMediaPlaying(bool* isMediaPlaying) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isMediaPlaying = detach_from<bool>(this->shim().IsMediaPlaying());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Shutdown() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Shutdown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs>
    {
        int32_t __stdcall get_NewItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().NewItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OldItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().OldItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2> : produce_base<D, winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItemChangedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreak> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreak>
    {
        int32_t __stdcall get_PlaybackList(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackList>(this->shim().PlaybackList());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PresentationPosition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().PresentationPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InsertionMethod(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreakInsertionMethod>(this->shim().InsertionMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().CustomProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanStart(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanStart(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanStart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreakEndedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreakEndedEventArgs>
    {
        int32_t __stdcall get_MediaBreak(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().MediaBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreakFactory> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreakFactory>
    {
        int32_t __stdcall Create(int32_t insertionMethod, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::Playback::MediaBreakInsertionMethod const*>(&insertionMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithPresentationPosition(int32_t insertionMethod, int64_t presentationPosition, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().CreateWithPresentationPosition(*reinterpret_cast<winrt::Windows::Media::Playback::MediaBreakInsertionMethod const*>(&insertionMethod), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&presentationPosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreakManager> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreakManager>
    {
        int32_t __stdcall add_BreaksSeekedOver(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BreaksSeekedOver(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BreaksSeekedOver(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BreaksSeekedOver(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BreakStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BreakStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BreakStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BreakStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BreakEnded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BreakEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakEndedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BreakEnded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BreakEnded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BreakSkipped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BreakSkipped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakManager, winrt::Windows::Media::Playback::MediaBreakSkippedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BreakSkipped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BreakSkipped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_CurrentBreak(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().CurrentBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackSession(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackSession>(this->shim().PlaybackSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PlayBreak(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlayBreak(*reinterpret_cast<winrt::Windows::Media::Playback::MediaBreak const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SkipCurrentBreak() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SkipCurrentBreak();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreakSchedule> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreakSchedule>
    {
        int32_t __stdcall add_ScheduleChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ScheduleChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaBreakSchedule, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ScheduleChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScheduleChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall InsertMidrollBreak(void* mediaBreak) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InsertMidrollBreak(*reinterpret_cast<winrt::Windows::Media::Playback::MediaBreak const*>(&mediaBreak));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveMidrollBreak(void* mediaBreak) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveMidrollBreak(*reinterpret_cast<winrt::Windows::Media::Playback::MediaBreak const*>(&mediaBreak));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MidrollBreaks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaBreak>>(this->shim().MidrollBreaks());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PrerollBreak(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrerollBreak(*reinterpret_cast<winrt::Windows::Media::Playback::MediaBreak const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrerollBreak(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().PrerollBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PostrollBreak(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PostrollBreak(*reinterpret_cast<winrt::Windows::Media::Playback::MediaBreak const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PostrollBreak(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().PostrollBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().PlaybackItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs>
    {
        int32_t __stdcall get_SeekedOverBreaks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaBreak>>(this->shim().SeekedOverBreaks());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OldPosition(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().OldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewPosition(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().NewPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreakSkippedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreakSkippedEventArgs>
    {
        int32_t __stdcall get_MediaBreak(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().MediaBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaBreakStartedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaBreakStartedEventArgs>
    {
        int32_t __stdcall get_MediaBreak(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreak>(this->shim().MediaBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaEnginePlaybackSource> : produce_base<D, winrt::Windows::Media::Playback::IMediaEnginePlaybackSource>
    {
        int32_t __stdcall get_CurrentItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().CurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPlaybackSource(void* source) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPlaybackSource(*reinterpret_cast<winrt::Windows::Media::Playback::IMediaPlaybackSource const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaItemDisplayProperties> : produce_base<D, winrt::Windows::Media::Playback::IMediaItemDisplayProperties>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaPlaybackType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Type(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Type(*reinterpret_cast<winrt::Windows::Media::MediaPlaybackType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MusicProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MusicDisplayProperties>(this->shim().MusicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoDisplayProperties>(this->shim().VideoProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Thumbnail(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Thumbnail(*reinterpret_cast<winrt::Windows::Storage::Streams::RandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearAll() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManager> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManager>
    {
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
        int32_t __stdcall get_MediaPlayer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlayer>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlayBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PlayBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PauseBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PauseBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NextBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().NextBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreviousBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PreviousBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FastForwardBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().FastForwardBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RewindBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().RewindBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShuffleBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().ShuffleBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoRepeatModeBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().AutoRepeatModeBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PositionBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RateBehavior(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().RateBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PlayReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlayReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlayReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlayReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PauseReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PauseReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PauseReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PauseReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NextReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NextReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NextReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NextReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PreviousReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PreviousReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PreviousReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreviousReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_FastForwardReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FastForwardReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FastForwardReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FastForwardReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RewindReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RewindReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RewindReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RewindReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ShuffleReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ShuffleReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ShuffleReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShuffleReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AutoRepeatModeReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AutoRepeatModeReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AutoRepeatModeReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoRepeatModeReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PositionReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PositionReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PositionReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RateReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RateReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManager, winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RateReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RateReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>
    {
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
        int32_t __stdcall get_AutoRepeatMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaPlaybackAutoRepeatMode>(this->shim().AutoRepeatMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior>
    {
        int32_t __stdcall get_CommandManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManager>(this->shim().CommandManager());
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
        int32_t __stdcall get_EnablingRule(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaCommandEnablingRule>(this->shim().EnablingRule());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnablingRule(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnablingRule(*reinterpret_cast<winrt::Windows::Media::Playback::MediaCommandEnablingRule const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_IsEnabledChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsEnabledChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsEnabledChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs>
    {
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
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs>
    {
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
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs>
    {
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
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs>
    {
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
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs>
    {
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
        int32_t __stdcall get_Position(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs>
    {
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
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs>
    {
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
        int32_t __stdcall get_PlaybackRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs>
    {
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
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs>
    {
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
        int32_t __stdcall get_IsShuffleRequested(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsShuffleRequested());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItem> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItem>
    {
        int32_t __stdcall add_AudioTracksChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AudioTracksChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AudioTracksChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioTracksChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VideoTracksChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VideoTracksChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VideoTracksChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoTracksChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TimedMetadataTracksChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TimedMetadataTracksChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackItem, winrt::Windows::Foundation::Collections::IVectorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TimedMetadataTracksChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TimedMetadataTracksChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioTracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackAudioTrackList>(this->shim().AudioTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoTracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackVideoTrackList>(this->shim().VideoTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimedMetadataTracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList>(this->shim().TimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItem2> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItem2>
    {
        int32_t __stdcall get_BreakSchedule(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreakSchedule>(this->shim().BreakSchedule());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DurationLimit(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().DurationLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanSkip(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSkip());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CanSkip(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanSkip(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDisplayProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaItemDisplayProperties>(this->shim().GetDisplayProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ApplyDisplayProperties(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplyDisplayProperties(*reinterpret_cast<winrt::Windows::Media::Playback::MediaItemDisplayProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItem3> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItem3>
    {
        int32_t __stdcall get_IsDisabledInPlaybackList(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDisabledInPlaybackList());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsDisabledInPlaybackList(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDisabledInPlaybackList(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TotalDownloadProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().TotalDownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoLoadedDisplayProperties(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::AutoLoadedDisplayPropertyKind>(this->shim().AutoLoadedDisplayProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoLoadedDisplayProperties(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoLoadedDisplayProperties(*reinterpret_cast<winrt::Windows::Media::Playback::AutoLoadedDisplayPropertyKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItemError> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItemError>
    {
        int32_t __stdcall get_ErrorCode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItemErrorCode>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItemFactory> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItemFactory>
    {
        int32_t __stdcall Create(void* source, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::Core::MediaSource const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItemFactory2> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItemFactory2>
    {
        int32_t __stdcall CreateWithStartTime(void* source, int64_t startTime, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().CreateWithStartTime(*reinterpret_cast<winrt::Windows::Media::Core::MediaSource const*>(&source), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&startTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithStartTimeAndDurationLimit(void* source, int64_t startTime, int64_t durationLimit, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().CreateWithStartTimeAndDurationLimit(*reinterpret_cast<winrt::Windows::Media::Core::MediaSource const*>(&source), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&startTime), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&durationLimit)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs>
    {
        int32_t __stdcall get_Item(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Error(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItemError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs>
    {
        int32_t __stdcall get_Item(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackItemStatics> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackItemStatics>
    {
        int32_t __stdcall FindFromMediaSource(void* source, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().FindFromMediaSource(*reinterpret_cast<winrt::Windows::Media::Core::MediaSource const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackList> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackList>
    {
        int32_t __stdcall add_ItemFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ItemFailed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ItemFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CurrentItemChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentItemChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentItemChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentItemChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ItemOpened(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ItemOpened(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackList, winrt::Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ItemOpened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemOpened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Items(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Playback::MediaPlaybackItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoRepeatEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoRepeatEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoRepeatEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoRepeatEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShuffleEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShuffleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShuffleEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShuffleEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().CurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentItemIndex(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CurrentItemIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveNext(void** item) noexcept final try
        {
            clear_abi(item);
            typename D::abi_guard guard(this->shim());
            *item = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().MoveNext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MovePrevious(void** item) noexcept final try
        {
            clear_abi(item);
            typename D::abi_guard guard(this->shim());
            *item = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().MovePrevious());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveTo(uint32_t itemIndex, void** item) noexcept final try
        {
            clear_abi(item);
            typename D::abi_guard guard(this->shim());
            *item = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().MoveTo(itemIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackList2> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackList2>
    {
        int32_t __stdcall get_MaxPrefetchTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().MaxPrefetchTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxPrefetchTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxPrefetchTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartingItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().StartingItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartingItem(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartingItem(*reinterpret_cast<winrt::Windows::Media::Playback::MediaPlaybackItem const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShuffledItems(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Playback::MediaPlaybackItem>>(this->shim().ShuffledItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetShuffledItems(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetShuffledItems(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Playback::MediaPlaybackItem> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackList3> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackList3>
    {
        int32_t __stdcall get_MaxPlayedItemsToKeepOpen(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().MaxPlayedItemsToKeepOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxPlayedItemsToKeepOpen(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxPlayedItemsToKeepOpen(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackSession> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackSession>
    {
        int32_t __stdcall add_PlaybackStateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlaybackStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlaybackStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PlaybackRateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlaybackRateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlaybackRateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackRateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SeekCompleted(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SeekCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SeekCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SeekCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BufferingStarted(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BufferingStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BufferingStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BufferingStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BufferingEnded(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BufferingEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BufferingEnded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BufferingEnded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BufferingProgressChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BufferingProgressChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BufferingProgressChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BufferingProgressChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DownloadProgressChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DownloadProgressChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DownloadProgressChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DownloadProgressChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NaturalDurationChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NaturalDurationChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NaturalDurationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NaturalDurationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PositionChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PositionChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PositionChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NaturalVideoSizeChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NaturalVideoSizeChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NaturalVideoSizeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NaturalVideoSizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_MediaPlayer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlayer>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().NaturalDuration());
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
        int32_t __stdcall put_Position(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackState>(this->shim().PlaybackState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanSeek(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanPause(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanPause());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsProtected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsProtected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PlaybackRate(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BufferingProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().BufferingProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DownloadProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalVideoHeight(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().NaturalVideoHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalVideoWidth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().NaturalVideoWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NormalizedSourceRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().NormalizedSourceRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NormalizedSourceRect(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NormalizedSourceRect(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StereoscopicVideoPackingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode>(this->shim().StereoscopicVideoPackingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StereoscopicVideoPackingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StereoscopicVideoPackingMode(*reinterpret_cast<winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackSession2> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackSession2>
    {
        int32_t __stdcall add_BufferedRangesChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BufferedRangesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BufferedRangesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BufferedRangesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PlayedRangesChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlayedRangesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlayedRangesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlayedRangesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SeekableRangesChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SeekableRangesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SeekableRangesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SeekableRangesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SupportedPlaybackRatesChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SupportedPlaybackRatesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackSession, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SupportedPlaybackRatesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SupportedPlaybackRatesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_SphericalVideoProjection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackSphericalVideoProjection>(this->shim().SphericalVideoProjection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMirroring(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsMirroring(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMirroring(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBufferedRanges(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>>(this->shim().GetBufferedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPlayedRanges(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>>(this->shim().GetPlayedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSeekableRanges(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaTimeRange>>(this->shim().GetSeekableRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSupportedPlaybackRateRange(double rate1, double rate2, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSupportedPlaybackRateRange(rate1, rate2));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackSession3> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackSession3>
    {
        int32_t __stdcall get_PlaybackRotation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaRotation>(this->shim().PlaybackRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PlaybackRotation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackRotation(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOutputDegradationPolicyState(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState>(this->shim().GetOutputDegradationPolicyState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs>
    {
        int32_t __stdcall get_IsPlaybackInterruption(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlaybackInterruption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState>
    {
        int32_t __stdcall get_VideoConstrictionReason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason>(this->shim().VideoConstrictionReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackSource> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackSource>
    {
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection>
    {
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
        int32_t __stdcall get_FrameFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat>(this->shim().FrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FrameFormat(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameFormat(*reinterpret_cast<winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalFieldOfViewInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalFieldOfViewInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalFieldOfViewInDegrees(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalFieldOfViewInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewOrientation(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().ViewOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ViewOrientation(winrt::Windows::Foundation::Numerics::quaternion value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ViewOrientation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProjectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::SphericalVideoProjectionMode>(this->shim().ProjectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProjectionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProjectionMode(*reinterpret_cast<winrt::Windows::Media::Playback::SphericalVideoProjectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList>
    {
        int32_t __stdcall add_PresentationModeChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PresentationModeChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, winrt::Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PresentationModeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PresentationModeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetPresentationMode(uint32_t index, int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode>(this->shim().GetPresentationMode(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPresentationMode(uint32_t index, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPresentationMode(index, *reinterpret_cast<winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayer> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayer>
    {
        int32_t __stdcall get_AutoPlay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoPlay(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoPlay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().NaturalDuration());
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
        int32_t __stdcall put_Position(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BufferingProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().BufferingProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlayerState>(this->shim().CurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanSeek(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanPause(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanPause());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLoopingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLoopingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsLoopingEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsLoopingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsProtected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsProtected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMuted(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMuted());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsMuted(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMuted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PlaybackRate(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Volume(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Volume());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Volume(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Volume(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackMediaMarkers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::PlaybackMediaMarkerSequence>(this->shim().PlaybackMediaMarkers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MediaOpened(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MediaOpened(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MediaOpened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaOpened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MediaEnded(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MediaEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MediaEnded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaEnded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MediaFailed(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MediaFailed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::MediaPlayerFailedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MediaFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CurrentStateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PlaybackMediaMarkerReached(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlaybackMediaMarkerReached(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlaybackMediaMarkerReached(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackMediaMarkerReached(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MediaPlayerRateChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MediaPlayerRateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MediaPlayerRateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaPlayerRateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VolumeChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VolumeChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VolumeChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VolumeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SeekCompleted(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SeekCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SeekCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SeekCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BufferingStarted(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BufferingStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BufferingStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BufferingStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BufferingEnded(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BufferingEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BufferingEnded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BufferingEnded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Play() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Play();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Pause() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetUriSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetUriSource(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayer2> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayer2>
    {
        int32_t __stdcall get_SystemMediaTransportControls(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SystemMediaTransportControls>(this->shim().SystemMediaTransportControls());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioCategory(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlayerAudioCategory>(this->shim().AudioCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioCategory(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioCategory(*reinterpret_cast<winrt::Windows::Media::Playback::MediaPlayerAudioCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioDeviceType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlayerAudioDeviceType>(this->shim().AudioDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioDeviceType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioDeviceType(*reinterpret_cast<winrt::Windows::Media::Playback::MediaPlayerAudioDeviceType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayer3> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayer3>
    {
        int32_t __stdcall add_IsMutedChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsMutedChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsMutedChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsMutedChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourceChanged(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_AudioBalance(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AudioBalance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioBalance(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioBalance(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RealTimePlayback(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().RealTimePlayback());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RealTimePlayback(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RealTimePlayback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StereoscopicVideoRenderMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::StereoscopicVideoRenderMode>(this->shim().StereoscopicVideoRenderMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StereoscopicVideoRenderMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StereoscopicVideoRenderMode(*reinterpret_cast<winrt::Windows::Media::Playback::StereoscopicVideoRenderMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BreakManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaBreakManager>(this->shim().BreakManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommandManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackCommandManager>(this->shim().CommandManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().AudioDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioDevice(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioDevice(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimelineController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaTimelineController>(this->shim().TimelineController());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TimelineController(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TimelineController(*reinterpret_cast<winrt::Windows::Media::MediaTimelineController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimelineControllerPositionOffset(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().TimelineControllerPositionOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TimelineControllerPositionOffset(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TimelineControllerPositionOffset(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackSession(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackSession>(this->shim().PlaybackSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StepForwardOneFrame() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StepForwardOneFrame();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StepBackwardOneFrame() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StepBackwardOneFrame();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAsCastingSource(void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Media::Casting::CastingSource>(this->shim().GetAsCastingSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayer4> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayer4>
    {
        int32_t __stdcall SetSurfaceSize(winrt::Windows::Foundation::Size size) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSurfaceSize(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&size));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSurface(void* compositor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Playback::MediaPlayerSurface>(this->shim().GetSurface(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayer5> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayer5>
    {
        int32_t __stdcall add_VideoFrameAvailable(void* value, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VideoFrameAvailable(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VideoFrameAvailable(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VideoFrameAvailable(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_IsVideoFrameServerEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVideoFrameServerEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsVideoFrameServerEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsVideoFrameServerEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyFrameToVideoSurface(void* destination) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CopyFrameToVideoSurface(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyFrameToVideoSurfaceWithTargetRectangle(void* destination, winrt::Windows::Foundation::Rect targetRectangle) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CopyFrameToVideoSurface(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&targetRectangle));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyFrameToStereoscopicVideoSurfaces(void* destinationLeftEye, void* destinationRightEye) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CopyFrameToStereoscopicVideoSurfaces(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destinationLeftEye), *reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destinationRightEye));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayer6> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayer6>
    {
        int32_t __stdcall add_SubtitleFrameChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SubtitleFrameChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Playback::MediaPlayer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SubtitleFrameChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SubtitleFrameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall RenderSubtitlesToSurface(void* destination, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().RenderSubtitlesToSurface(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RenderSubtitlesToSurfaceWithTargetRectangle(void* destination, winrt::Windows::Foundation::Rect targetRectangle, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().RenderSubtitlesToSurface(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&targetRectangle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayer7> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayer7>
    {
        int32_t __stdcall get_AudioStateMonitor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().AudioStateMonitor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerEffects> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerEffects>
    {
        int32_t __stdcall AddAudioEffect(void* activatableClassId, bool effectOptional, void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddAudioEffect(*reinterpret_cast<hstring const*>(&activatableClassId), effectOptional, *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveAllEffects() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveAllEffects();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerEffects2> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerEffects2>
    {
        int32_t __stdcall AddVideoEffect(void* activatableClassId, bool effectOptional, void* effectConfiguration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddVideoEffect(*reinterpret_cast<hstring const*>(&activatableClassId), effectOptional, *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&effectConfiguration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs>
    {
        int32_t __stdcall get_Error(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlayerError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedErrorCode(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ErrorMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerRateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerRateChangedEventArgs>
    {
        int32_t __stdcall get_NewRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().NewRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerSource> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerSource>
    {
        int32_t __stdcall get_ProtectionManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::MediaProtectionManager>(this->shim().ProtectionManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProtectionManager(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProtectionManager(*reinterpret_cast<winrt::Windows::Media::Protection::MediaProtectionManager const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFileSource(void* file) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFileSource(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStreamSource(void* stream) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStreamSource(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetMediaSource(void* source) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetMediaSource(*reinterpret_cast<winrt::Windows::Media::Core::IMediaSource const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerSource2> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerSource2>
    {
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::IMediaPlaybackSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Source(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Source(*reinterpret_cast<winrt::Windows::Media::Playback::IMediaPlaybackSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IMediaPlayerSurface> : produce_base<D, winrt::Windows::Media::Playback::IMediaPlayerSurface>
    {
        int32_t __stdcall get_CompositionSurface(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ICompositionSurface>(this->shim().CompositionSurface());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Compositor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Compositor>(this->shim().Compositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaPlayer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlayer>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IPlaybackMediaMarker> : produce_base<D, winrt::Windows::Media::Playback::IPlaybackMediaMarker>
    {
        int32_t __stdcall get_Time(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Time());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaMarkerType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MediaMarkerType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IPlaybackMediaMarkerFactory> : produce_base<D, winrt::Windows::Media::Playback::IPlaybackMediaMarkerFactory>
    {
        int32_t __stdcall CreateFromTime(int64_t value, void** marker) noexcept final try
        {
            clear_abi(marker);
            typename D::abi_guard guard(this->shim());
            *marker = detach_from<winrt::Windows::Media::Playback::PlaybackMediaMarker>(this->shim().CreateFromTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Create(int64_t value, void* mediaMarketType, void* text, void** marker) noexcept final try
        {
            clear_abi(marker);
            typename D::abi_guard guard(this->shim());
            *marker = detach_from<winrt::Windows::Media::Playback::PlaybackMediaMarker>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value), *reinterpret_cast<hstring const*>(&mediaMarketType), *reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs>
    {
        int32_t __stdcall get_PlaybackMediaMarker(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::PlaybackMediaMarker>(this->shim().PlaybackMediaMarker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence> : produce_base<D, winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence>
    {
        int32_t __stdcall get_Size(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Insert(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Insert(*reinterpret_cast<winrt::Windows::Media::Playback::PlaybackMediaMarker const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Clear() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs> : produce_base<D, winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs>
    {
        int32_t __stdcall get_Track(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedMetadataTrack>(this->shim().Track());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OldPresentationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode>(this->shim().OldPresentationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewPresentationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::TimedMetadataTrackPresentationMode>(this->shim().NewPresentationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Playback
{
    inline auto BackgroundMediaPlayer::Current()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Playback::MediaPlayer(*)(IBackgroundMediaPlayerStatics const&), BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([](IBackgroundMediaPlayerStatics const& f) { return f.Current(); });
    }
    inline auto BackgroundMediaPlayer::MessageReceivedFromBackground(winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
    {
        return impl::call_factory<BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([&](IBackgroundMediaPlayerStatics const& f) { return f.MessageReceivedFromBackground(value); });
    }
    inline BackgroundMediaPlayer::MessageReceivedFromBackground_revoker BackgroundMediaPlayer::MessageReceivedFromBackground(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
    {
        auto f = get_activation_factory<BackgroundMediaPlayer, winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics>();
        return { f, f.MessageReceivedFromBackground(value) };
    }
    inline auto BackgroundMediaPlayer::MessageReceivedFromBackground(winrt::event_token const& token)
    {
        impl::call_factory<BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([&](IBackgroundMediaPlayerStatics const& f) { return f.MessageReceivedFromBackground(token); });
    }
    inline auto BackgroundMediaPlayer::MessageReceivedFromForeground(winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
    {
        return impl::call_factory<BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([&](IBackgroundMediaPlayerStatics const& f) { return f.MessageReceivedFromForeground(value); });
    }
    inline BackgroundMediaPlayer::MessageReceivedFromForeground_revoker BackgroundMediaPlayer::MessageReceivedFromForeground(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
    {
        auto f = get_activation_factory<BackgroundMediaPlayer, winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics>();
        return { f, f.MessageReceivedFromForeground(value) };
    }
    inline auto BackgroundMediaPlayer::MessageReceivedFromForeground(winrt::event_token const& token)
    {
        impl::call_factory<BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([&](IBackgroundMediaPlayerStatics const& f) { return f.MessageReceivedFromForeground(token); });
    }
    inline auto BackgroundMediaPlayer::SendMessageToBackground(winrt::Windows::Foundation::Collections::ValueSet const& value)
    {
        impl::call_factory<BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([&](IBackgroundMediaPlayerStatics const& f) { return f.SendMessageToBackground(value); });
    }
    inline auto BackgroundMediaPlayer::SendMessageToForeground(winrt::Windows::Foundation::Collections::ValueSet const& value)
    {
        impl::call_factory<BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([&](IBackgroundMediaPlayerStatics const& f) { return f.SendMessageToForeground(value); });
    }
    inline auto BackgroundMediaPlayer::IsMediaPlaying()
    {
        return impl::call_factory_cast<bool(*)(IBackgroundMediaPlayerStatics const&), BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([](IBackgroundMediaPlayerStatics const& f) { return f.IsMediaPlaying(); });
    }
    inline auto BackgroundMediaPlayer::Shutdown()
    {
        impl::call_factory_cast<void(*)(IBackgroundMediaPlayerStatics const&), BackgroundMediaPlayer, IBackgroundMediaPlayerStatics>([](IBackgroundMediaPlayerStatics const& f) { return f.Shutdown(); });
    }
    inline MediaBreak::MediaBreak(winrt::Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod) :
        MediaBreak(impl::call_factory<MediaBreak, IMediaBreakFactory>([&](IMediaBreakFactory const& f) { return f.Create(insertionMethod); }))
    {
    }
    inline MediaBreak::MediaBreak(winrt::Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod, winrt::Windows::Foundation::TimeSpan const& presentationPosition) :
        MediaBreak(impl::call_factory<MediaBreak, IMediaBreakFactory>([&](IMediaBreakFactory const& f) { return f.CreateWithPresentationPosition(insertionMethod, presentationPosition); }))
    {
    }
    inline MediaPlaybackItem::MediaPlaybackItem(winrt::Windows::Media::Core::MediaSource const& source) :
        MediaPlaybackItem(impl::call_factory<MediaPlaybackItem, IMediaPlaybackItemFactory>([&](IMediaPlaybackItemFactory const& f) { return f.Create(source); }))
    {
    }
    inline MediaPlaybackItem::MediaPlaybackItem(winrt::Windows::Media::Core::MediaSource const& source, winrt::Windows::Foundation::TimeSpan const& startTime) :
        MediaPlaybackItem(impl::call_factory<MediaPlaybackItem, IMediaPlaybackItemFactory2>([&](IMediaPlaybackItemFactory2 const& f) { return f.CreateWithStartTime(source, startTime); }))
    {
    }
    inline MediaPlaybackItem::MediaPlaybackItem(winrt::Windows::Media::Core::MediaSource const& source, winrt::Windows::Foundation::TimeSpan const& startTime, winrt::Windows::Foundation::TimeSpan const& durationLimit) :
        MediaPlaybackItem(impl::call_factory<MediaPlaybackItem, IMediaPlaybackItemFactory2>([&](IMediaPlaybackItemFactory2 const& f) { return f.CreateWithStartTimeAndDurationLimit(source, startTime, durationLimit); }))
    {
    }
    inline auto MediaPlaybackItem::FindFromMediaSource(winrt::Windows::Media::Core::MediaSource const& source)
    {
        return impl::call_factory<MediaPlaybackItem, IMediaPlaybackItemStatics>([&](IMediaPlaybackItemStatics const& f) { return f.FindFromMediaSource(source); });
    }
    inline MediaPlaybackList::MediaPlaybackList() :
        MediaPlaybackList(impl::call_factory_cast<MediaPlaybackList(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaPlaybackList>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaPlaybackList>(); }))
    {
    }
    inline MediaPlayer::MediaPlayer() :
        MediaPlayer(impl::call_factory_cast<MediaPlayer(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaPlayer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaPlayer>(); }))
    {
    }
    inline PlaybackMediaMarker::PlaybackMediaMarker(winrt::Windows::Foundation::TimeSpan const& value) :
        PlaybackMediaMarker(impl::call_factory<PlaybackMediaMarker, IPlaybackMediaMarkerFactory>([&](IPlaybackMediaMarkerFactory const& f) { return f.CreateFromTime(value); }))
    {
    }
    inline PlaybackMediaMarker::PlaybackMediaMarker(winrt::Windows::Foundation::TimeSpan const& value, param::hstring const& mediaMarketType, param::hstring const& text) :
        PlaybackMediaMarker(impl::call_factory<PlaybackMediaMarker, IPlaybackMediaMarkerFactory>([&](IPlaybackMediaMarkerFactory const& f) { return f.Create(value, mediaMarketType, text); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreak> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakEndedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakSchedule> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakSkippedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaEnginePlaybackSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaItemDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItem2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItem3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemFactory2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackList2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackList3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSession2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSession3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerEffects> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerEffects2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerRateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerSurface> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarkerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::BackgroundMediaPlayer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaBreak> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaBreakEndedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaBreakManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaBreakSchedule> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaBreakSeekedOverEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaBreakSkippedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaBreakStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaItemDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackAudioTrackList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItemError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSessionBufferingStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSphericalVideoProjection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackVideoTrackList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlayer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerRateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerSurface> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::PlaybackMediaMarker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::PlaybackMediaMarkerSequence> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
