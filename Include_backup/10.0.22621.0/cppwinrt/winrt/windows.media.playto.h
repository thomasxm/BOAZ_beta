// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_PlayTo_H
#define WINRT_Windows_Media_PlayTo_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.PlayTo.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_PlayTo_ICurrentTimeChangeRequestedEventArgs<D>::Time() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs)->get_Time(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IMuteChangeRequestedEventArgs<D>::Mute() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IMuteChangeRequestedEventArgs)->get_Mute(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToConnectionState) consume_Windows_Media_PlayTo_IPlayToConnection<D>::State() const
    {
        winrt::Windows::Media::PlayTo::PlayToConnectionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnection)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnection)->add_StateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged_revoker consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnection)->remove_StateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnection)->add_Transferred(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred_revoker consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Transferred_revoker>(this, Transferred(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnection)->remove_Transferred(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnection)->add_Error(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error_revoker consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Error_revoker>(this, Error(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnection)->remove_Error(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToConnectionError) consume_Windows_Media_PlayTo_IPlayToConnectionErrorEventArgs<D>::Code() const
    {
        winrt::Windows::Media::PlayTo::PlayToConnectionError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs)->get_Code(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_IPlayToConnectionErrorEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToConnectionState) consume_Windows_Media_PlayTo_IPlayToConnectionStateChangedEventArgs<D>::PreviousState() const
    {
        winrt::Windows::Media::PlayTo::PlayToConnectionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs)->get_PreviousState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToConnectionState) consume_Windows_Media_PlayTo_IPlayToConnectionStateChangedEventArgs<D>::CurrentState() const
    {
        winrt::Windows::Media::PlayTo::PlayToConnectionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs)->get_CurrentState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToSource) consume_Windows_Media_PlayTo_IPlayToConnectionTransferredEventArgs<D>::PreviousSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs)->get_PreviousSource(&value));
        return winrt::Windows::Media::PlayTo::PlayToSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToSource) consume_Windows_Media_PlayTo_IPlayToConnectionTransferredEventArgs<D>::CurrentSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs)->get_CurrentSource(&value));
        return winrt::Windows::Media::PlayTo::PlayToSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToManager, winrt::Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManager)->add_SourceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested_revoker consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToManager, winrt::Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourceRequested_revoker>(this, SourceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManager)->remove_SourceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToManager, winrt::Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManager)->add_SourceSelected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected_revoker consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToManager, winrt::Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourceSelected_revoker>(this, SourceSelected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManager)->remove_SourceSelected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToManager<D>::DefaultSourceSelection(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManager)->put_DefaultSourceSelection(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IPlayToManager<D>::DefaultSourceSelection() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManager)->get_DefaultSourceSelection(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToManager) consume_Windows_Media_PlayTo_IPlayToManagerStatics<D>::GetForCurrentView() const
    {
        void* playToManager{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManagerStatics)->GetForCurrentView(&playToManager));
        return winrt::Windows::Media::PlayTo::PlayToManager{ playToManager, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToManagerStatics<D>::ShowPlayToUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToManagerStatics)->ShowPlayToUI());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_PlayRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PlayRequested_revoker>(this, PlayRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_PlayRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_PauseRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PauseRequested_revoker>(this, PauseRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_PauseRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::SourceChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_SourceChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::SourceChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SourceChangeRequested_revoker>(this, SourceChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_SourceChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_PlaybackRateChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PlaybackRateChangeRequested_revoker>(this, PlaybackRateChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_PlaybackRateChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_CurrentTimeChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CurrentTimeChangeRequested_revoker>(this, CurrentTimeChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_CurrentTimeChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::MuteChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_MuteChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::MuteChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, MuteChangeRequested_revoker>(this, MuteChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_MuteChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_VolumeChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, VolumeChangeRequested_revoker>(this, VolumeChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_VolumeChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_TimeUpdateRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, TimeUpdateRequested_revoker>(this, TimeUpdateRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_TimeUpdateRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->add_StopRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StopRequested_revoker>(this, StopRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->remove_StopRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyVolumeChange(double volume, bool mute) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyVolumeChange(volume, mute));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyRateChange(double rate) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyRateChange(rate));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyLoadedMetadata() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyLoadedMetadata());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyTimeUpdate(winrt::Windows::Foundation::TimeSpan const& currentTime) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyTimeUpdate(impl::bind_in(currentTime)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyDurationChange(winrt::Windows::Foundation::TimeSpan const& duration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyDurationChange(impl::bind_in(duration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifySeeking() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifySeeking());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifySeeked() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifySeeked());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyPaused() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyPaused());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyPlaying() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyPlaying());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyEnded() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyEnded());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyError() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyError());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyStopped() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->NotifyStopped());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::FriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->get_FriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::FriendlyName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->put_FriendlyName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsImage(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->put_SupportsImage(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsImage() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->get_SupportsImage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsAudio(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->put_SupportsAudio(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsAudio() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->get_SupportsAudio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsVideo(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->put_SupportsVideo(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsVideo() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->get_SupportsVideo(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StartAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->StartAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToReceiver)->StopAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToConnection) consume_Windows_Media_PlayTo_IPlayToSource<D>::Connection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSource)->get_Connection(&value));
        return winrt::Windows::Media::PlayTo::PlayToConnection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToSource) consume_Windows_Media_PlayTo_IPlayToSource<D>::Next() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSource)->get_Next(&value));
        return winrt::Windows::Media::PlayTo::PlayToSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToSource<D>::Next(winrt::Windows::Media::PlayTo::PlayToSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSource)->put_Next(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToSource<D>::PlayNext() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSource)->PlayNext());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToSourceDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::Deadline() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceRequest)->get_Deadline(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::DisplayErrorString(param::hstring const& errorString) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceRequest)->DisplayErrorString(*(void**)(&errorString)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToSourceDeferral) consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceRequest)->GetDeferral(&deferral));
        return winrt::Windows::Media::PlayTo::PlayToSourceDeferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::SetSource(winrt::Windows::Media::PlayTo::PlayToSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceRequest)->SetSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::PlayTo::PlayToSourceRequest) consume_Windows_Media_PlayTo_IPlayToSourceRequestedEventArgs<D>::SourceRequest() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs)->get_SourceRequest(&value));
        return winrt::Windows::Media::PlayTo::PlayToSourceRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::FriendlyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_FriendlyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType) consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::Icon() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_Icon(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::SupportsImage() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_SupportsImage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::SupportsAudio() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_SupportsAudio(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::SupportsVideo() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_SupportsVideo(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_PlayTo_IPlayToSourceWithPreferredSourceUri<D>::PreferredSourceUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri)->get_PreferredSourceUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_PlayTo_IPlayToSourceWithPreferredSourceUri<D>::PreferredSourceUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri)->put_PreferredSourceUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_PlayTo_IPlaybackRateChangeRequestedEventArgs<D>::Rate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs)->get_Rate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Stream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Stream(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Author() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Author(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Album() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Album(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Genre() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Genre(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Date() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Date(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Rating() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Rating(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_PlayTo_IVolumeChangeRequestedEventArgs<D>::Volume() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs)->get_Volume(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs>
    {
        int32_t __stdcall get_Time(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Time());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IMuteChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IMuteChangeRequestedEventArgs>
    {
        int32_t __stdcall get_Mute(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Mute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToConnection> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToConnection>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToConnectionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Transferred(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Transferred(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Transferred(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Transferred(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Error(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Error(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToConnection, winrt::Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Error(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Error(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs>
    {
        int32_t __stdcall get_Code(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToConnectionError>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs>
    {
        int32_t __stdcall get_PreviousState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToConnectionState>(this->shim().PreviousState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToConnectionState>(this->shim().CurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs>
    {
        int32_t __stdcall get_PreviousSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToSource>(this->shim().PreviousSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToSource>(this->shim().CurrentSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToManager> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToManager>
    {
        int32_t __stdcall add_SourceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToManager, winrt::Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourceSelected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceSelected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToManager, winrt::Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceSelected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceSelected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall put_DefaultSourceSelection(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultSourceSelection(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultSourceSelection(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DefaultSourceSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToManagerStatics> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToManagerStatics>
    {
        int32_t __stdcall GetForCurrentView(void** playToManager) noexcept final try
        {
            clear_abi(playToManager);
            typename D::abi_guard guard(this->shim());
            *playToManager = detach_from<winrt::Windows::Media::PlayTo::PlayToManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowPlayToUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowPlayToUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToReceiver> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToReceiver>
    {
        int32_t __stdcall add_PlayRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlayRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlayRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlayRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PauseRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PauseRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PauseRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PauseRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourceChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::SourceChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PlaybackRateChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlaybackRateChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlaybackRateChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackRateChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CurrentTimeChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentTimeChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentTimeChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentTimeChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_MuteChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MuteChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::MuteChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MuteChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MuteChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_VolumeChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().VolumeChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VolumeChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VolumeChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TimeUpdateRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TimeUpdateRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TimeUpdateRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TimeUpdateRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_StopRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StopRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::PlayTo::PlayToReceiver, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StopRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall NotifyVolumeChange(double volume, bool mute) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyVolumeChange(volume, mute);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyRateChange(double rate) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyRateChange(rate);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyLoadedMetadata() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyLoadedMetadata();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyTimeUpdate(int64_t currentTime) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyTimeUpdate(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&currentTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyDurationChange(int64_t duration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyDurationChange(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&duration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifySeeking() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifySeeking();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifySeeked() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifySeeked();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyPaused() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyPaused();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyPlaying() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyPlaying();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyEnded() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyEnded();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyError() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyError();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyStopped() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyStopped();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FriendlyName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FriendlyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SupportsImage(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SupportsImage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsImage(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SupportsAudio(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SupportsAudio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsAudio(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SupportsVideo(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SupportsVideo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsVideo(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToSource> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToSource>
    {
        int32_t __stdcall get_Connection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Next(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToSource>(this->shim().Next());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Next(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Next(*reinterpret_cast<winrt::Windows::Media::PlayTo::PlayToSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PlayNext() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlayNext();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToSourceDeferral> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToSourceDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToSourceRequest> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToSourceRequest>
    {
        int32_t __stdcall get_Deadline(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisplayErrorString(void* errorString) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayErrorString(*reinterpret_cast<hstring const*>(&errorString));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Media::PlayTo::PlayToSourceDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSource(*reinterpret_cast<winrt::Windows::Media::PlayTo::PlayToSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs>
    {
        int32_t __stdcall get_SourceRequest(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::PlayTo::PlayToSourceRequest>(this->shim().SourceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs>
    {
        int32_t __stdcall get_FriendlyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Icon(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsImage(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsAudio(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsVideo(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri> : produce_base<D, winrt::Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri>
    {
        int32_t __stdcall get_PreferredSourceUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().PreferredSourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreferredSourceUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreferredSourceUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs>
    {
        int32_t __stdcall get_Rate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Rate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs>
    {
        int32_t __stdcall get_Stream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().Stream());
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
        int32_t __stdcall get_Author(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Author());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Album(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Album());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Genre(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Genre());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Date(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().Date());
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
        int32_t __stdcall get_Rating(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().Rating());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs>
    {
        int32_t __stdcall get_Volume(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Volume());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::PlayTo
{
    inline auto PlayToManager::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::Media::PlayTo::PlayToManager(*)(IPlayToManagerStatics const&), PlayToManager, IPlayToManagerStatics>([](IPlayToManagerStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto PlayToManager::ShowPlayToUI()
    {
        impl::call_factory_cast<void(*)(IPlayToManagerStatics const&), PlayToManager, IPlayToManagerStatics>([](IPlayToManagerStatics const& f) { return f.ShowPlayToUI(); });
    }
    inline PlayToReceiver::PlayToReceiver() :
        PlayToReceiver(impl::call_factory_cast<PlayToReceiver(*)(winrt::Windows::Foundation::IActivationFactory const&), PlayToReceiver>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlayToReceiver>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IMuteChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToReceiver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::MuteChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToReceiver> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::SourceChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
