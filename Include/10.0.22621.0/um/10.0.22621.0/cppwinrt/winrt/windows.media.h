// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_H
#define WINRT_Windows_Media_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_IAudioBuffer<D>::Capacity() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IAudioBuffer)->get_Capacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_IAudioBuffer<D>::Length() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IAudioBuffer)->get_Length(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IAudioBuffer<D>::Length(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IAudioBuffer)->put_Length(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioBuffer) consume_Windows_Media_IAudioFrame<D>::LockBuffer(winrt::Windows::Media::AudioBufferAccessMode const& mode) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IAudioFrame)->LockBuffer(static_cast<int32_t>(mode), &value));
        return winrt::Windows::Media::AudioBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioFrame) consume_Windows_Media_IAudioFrameFactory<D>::Create(uint32_t capacity) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IAudioFrameFactory)->Create(capacity, &value));
        return winrt::Windows::Media::AudioFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaPlaybackAutoRepeatMode) consume_Windows_Media_IAutoRepeatModeChangeRequestedEventArgs<D>::RequestedAutoRepeatMode() const
    {
        winrt::Windows::Media::MediaPlaybackAutoRepeatMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs)->get_RequestedAutoRepeatMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IImageDisplayProperties<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IImageDisplayProperties)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IImageDisplayProperties<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IImageDisplayProperties)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IImageDisplayProperties<D>::Subtitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IImageDisplayProperties)->get_Subtitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IImageDisplayProperties<D>::Subtitle(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IImageDisplayProperties)->put_Subtitle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::SoundLevelChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_SoundLevelChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::SoundLevelChanged_revoker consume_Windows_Media_IMediaControl<D>::SoundLevelChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SoundLevelChanged_revoker>(this, SoundLevelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::SoundLevelChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_SoundLevelChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::PlayPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_PlayPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::PlayPressed_revoker consume_Windows_Media_IMediaControl<D>::PlayPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PlayPressed_revoker>(this, PlayPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::PlayPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_PlayPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::PausePressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_PausePressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::PausePressed_revoker consume_Windows_Media_IMediaControl<D>::PausePressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PausePressed_revoker>(this, PausePressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::PausePressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_PausePressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::StopPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_StopPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::StopPressed_revoker consume_Windows_Media_IMediaControl<D>::StopPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StopPressed_revoker>(this, StopPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::StopPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_StopPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_PlayPauseTogglePressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed_revoker consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PlayPauseTogglePressed_revoker>(this, PlayPauseTogglePressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::PlayPauseTogglePressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_PlayPauseTogglePressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::RecordPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_RecordPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::RecordPressed_revoker consume_Windows_Media_IMediaControl<D>::RecordPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RecordPressed_revoker>(this, RecordPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::RecordPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_RecordPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::NextTrackPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_NextTrackPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::NextTrackPressed_revoker consume_Windows_Media_IMediaControl<D>::NextTrackPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, NextTrackPressed_revoker>(this, NextTrackPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::NextTrackPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_NextTrackPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_PreviousTrackPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed_revoker consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, PreviousTrackPressed_revoker>(this, PreviousTrackPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::PreviousTrackPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_PreviousTrackPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::FastForwardPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_FastForwardPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::FastForwardPressed_revoker consume_Windows_Media_IMediaControl<D>::FastForwardPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, FastForwardPressed_revoker>(this, FastForwardPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::FastForwardPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_FastForwardPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::RewindPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_RewindPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::RewindPressed_revoker consume_Windows_Media_IMediaControl<D>::RewindPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, RewindPressed_revoker>(this, RewindPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::RewindPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_RewindPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::ChannelUpPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_ChannelUpPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::ChannelUpPressed_revoker consume_Windows_Media_IMediaControl<D>::ChannelUpPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ChannelUpPressed_revoker>(this, ChannelUpPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::ChannelUpPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_ChannelUpPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaControl<D>::ChannelDownPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->add_ChannelDownPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaControl<D>::ChannelDownPressed_revoker consume_Windows_Media_IMediaControl<D>::ChannelDownPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ChannelDownPressed_revoker>(this, ChannelDownPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::ChannelDownPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->remove_ChannelDownPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SoundLevel) consume_Windows_Media_IMediaControl<D>::SoundLevel() const
    {
        winrt::Windows::Media::SoundLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->get_SoundLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::TrackName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->put_TrackName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMediaControl<D>::TrackName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->get_TrackName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::ArtistName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->put_ArtistName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMediaControl<D>::ArtistName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->get_ArtistName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::IsPlaying(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->put_IsPlaying(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_IMediaControl<D>::IsPlaying() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->get_IsPlaying(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaControl<D>::AlbumArt(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->put_AlbumArt(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_IMediaControl<D>::AlbumArt() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaControl)->get_AlbumArt(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtension<D>::SetProperties(winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtension)->SetProperties(*(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterSchemeHandler(param::hstring const& activatableClassId, param::hstring const& scheme) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterSchemeHandler(*(void**)(&activatableClassId), *(void**)(&scheme)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterSchemeHandler(param::hstring const& activatableClassId, param::hstring const& scheme, winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterSchemeHandlerWithSettings(*(void**)(&activatableClassId), *(void**)(&scheme), *(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterByteStreamHandler(param::hstring const& activatableClassId, param::hstring const& fileExtension, param::hstring const& mimeType) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterByteStreamHandler(*(void**)(&activatableClassId), *(void**)(&fileExtension), *(void**)(&mimeType)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterByteStreamHandler(param::hstring const& activatableClassId, param::hstring const& fileExtension, param::hstring const& mimeType, winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterByteStreamHandlerWithSettings(*(void**)(&activatableClassId), *(void**)(&fileExtension), *(void**)(&mimeType), *(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterAudioDecoder(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterAudioDecoderWithSettings(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype), *(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterAudioEncoder(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterAudioEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterAudioEncoderWithSettings(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype), *(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterVideoDecoder(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoDecoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterVideoDecoderWithSettings(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype), *(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterVideoEncoder(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager<D>::RegisterVideoEncoder(param::hstring const& activatableClassId, winrt::guid const& inputSubtype, winrt::guid const& outputSubtype, winrt::Windows::Foundation::Collections::IPropertySet const& configuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager)->RegisterVideoEncoderWithSettings(*(void**)(&activatableClassId), impl::bind_in(inputSubtype), impl::bind_in(outputSubtype), *(void**)(&configuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaExtensionManager2<D>::RegisterMediaExtensionForAppService(winrt::Windows::Media::IMediaExtension const& extension, winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& connection) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaExtensionManager2)->RegisterMediaExtensionForAppService(*(void**)(&extension), *(void**)(&connection)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMediaFrame<D>::Type() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->get_Type(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_IMediaFrame<D>::IsReadOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->get_IsReadOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaFrame<D>::RelativeTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->put_RelativeTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_IMediaFrame<D>::RelativeTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->get_RelativeTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaFrame<D>::SystemRelativeTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->put_SystemRelativeTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_IMediaFrame<D>::SystemRelativeTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->get_SystemRelativeTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaFrame<D>::Duration(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->put_Duration(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_IMediaFrame<D>::Duration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->get_Duration(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaFrame<D>::IsDiscontinuous(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->put_IsDiscontinuous(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_IMediaFrame<D>::IsDiscontinuous() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->get_IsDiscontinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_IMediaFrame<D>::ExtendedProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaFrame)->get_ExtendedProperties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_IMediaMarker<D>::Time() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaMarker)->get_Time(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMediaMarker<D>::MediaMarkerType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaMarker)->get_MediaMarkerType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMediaMarker<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaMarker)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMediaMarkerTypesStatics<D>::Bookmark() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaMarkerTypesStatics)->get_Bookmark(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::IMediaMarker>) consume_Windows_Media_IMediaMarkers<D>::Markers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaMarkers)->get_Markers(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::IMediaMarker>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Media_IMediaProcessingTriggerDetails<D>::Arguments() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaProcessingTriggerDetails)->get_Arguments(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController<D>::Resume() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->Resume());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController<D>::Pause() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->Pause());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_IMediaTimelineController<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController<D>::Position(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_IMediaTimelineController<D>::ClockRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->get_ClockRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController<D>::ClockRate(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->put_ClockRate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaTimelineControllerState) consume_Windows_Media_IMediaTimelineController<D>::State() const
    {
        winrt::Windows::Media::MediaTimelineControllerState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaTimelineController<D>::PositionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const& positionChangedEventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->add_PositionChanged(*(void**)(&positionChangedEventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaTimelineController<D>::PositionChanged_revoker consume_Windows_Media_IMediaTimelineController<D>::PositionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const& positionChangedEventHandler) const
    {
        return impl::make_event_revoker<D, PositionChanged_revoker>(this, PositionChanged(positionChangedEventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController<D>::PositionChanged(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->remove_PositionChanged(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaTimelineController<D>::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const& stateChangedEventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->add_StateChanged(*(void**)(&stateChangedEventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Media_IMediaTimelineController<D>::StateChanged_revoker consume_Windows_Media_IMediaTimelineController<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const& stateChangedEventHandler) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(stateChangedEventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController<D>::StateChanged(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController)->remove_StateChanged(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_IMediaTimelineController2<D>::Duration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->get_Duration(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController2<D>::Duration(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->put_Duration(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_IMediaTimelineController2<D>::IsLoopingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->get_IsLoopingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController2<D>::IsLoopingEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->put_IsLoopingEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaTimelineController2<D>::Failed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Media::MediaTimelineControllerFailedEventArgs> const& eventHandler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->add_Failed(*(void**)(&eventHandler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_IMediaTimelineController2<D>::Failed_revoker consume_Windows_Media_IMediaTimelineController2<D>::Failed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Media::MediaTimelineControllerFailedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, Failed_revoker>(this, Failed(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController2<D>::Failed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->remove_Failed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_IMediaTimelineController2<D>::Ended(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const& eventHandler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->add_Ended(*(void**)(&eventHandler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_IMediaTimelineController2<D>::Ended_revoker consume_Windows_Media_IMediaTimelineController2<D>::Ended(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const& eventHandler) const
    {
        return impl::make_event_revoker<D, Ended_revoker>(this, Ended(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMediaTimelineController2<D>::Ended(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineController2)->remove_Ended(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_IMediaTimelineControllerFailedEventArgs<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMusicDisplayProperties<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMusicDisplayProperties<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMusicDisplayProperties<D>::AlbumArtist() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties)->get_AlbumArtist(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMusicDisplayProperties<D>::AlbumArtist(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties)->put_AlbumArtist(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMusicDisplayProperties<D>::Artist() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties)->get_Artist(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMusicDisplayProperties<D>::Artist(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties)->put_Artist(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IMusicDisplayProperties2<D>::AlbumTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties2)->get_AlbumTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMusicDisplayProperties2<D>::AlbumTitle(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties2)->put_AlbumTitle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_IMusicDisplayProperties2<D>::TrackNumber() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties2)->get_TrackNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMusicDisplayProperties2<D>::TrackNumber(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties2)->put_TrackNumber(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Media_IMusicDisplayProperties2<D>::Genres() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties2)->get_Genres(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_IMusicDisplayProperties3<D>::AlbumTrackCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties3)->get_AlbumTrackCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IMusicDisplayProperties3<D>::AlbumTrackCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IMusicDisplayProperties3)->put_AlbumTrackCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_IPlaybackPositionChangeRequestedEventArgs<D>::RequestedPlaybackPosition() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs)->get_RequestedPlaybackPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_IPlaybackRateChangeRequestedEventArgs<D>::RequestedPlaybackRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs)->get_RequestedPlaybackRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_IShuffleEnabledChangeRequestedEventArgs<D>::RequestedShuffleEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs)->get_RequestedShuffleEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaPlaybackStatus) consume_Windows_Media_ISystemMediaTransportControls<D>::PlaybackStatus() const
    {
        winrt::Windows::Media::MediaPlaybackStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_PlaybackStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::PlaybackStatus(winrt::Windows::Media::MediaPlaybackStatus const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_PlaybackStatus(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SystemMediaTransportControlsDisplayUpdater) consume_Windows_Media_ISystemMediaTransportControls<D>::DisplayUpdater() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_DisplayUpdater(&value));
        return winrt::Windows::Media::SystemMediaTransportControlsDisplayUpdater{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SoundLevel) consume_Windows_Media_ISystemMediaTransportControls<D>::SoundLevel() const
    {
        winrt::Windows::Media::SoundLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_SoundLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsPlayEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsPlayEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsPlayEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsPlayEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsStopEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsStopEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsStopEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsStopEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsPauseEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsPauseEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsPauseEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsPauseEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsRecordEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsRecordEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsRecordEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsRecordEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsFastForwardEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsFastForwardEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsFastForwardEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsFastForwardEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsRewindEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsRewindEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsRewindEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsRewindEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsPreviousEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsPreviousEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsPreviousEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsPreviousEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsNextEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsNextEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsNextEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsNextEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelUpEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsChannelUpEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelUpEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsChannelUpEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelDownEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->get_IsChannelDownEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::IsChannelDownEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->put_IsChannelDownEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->add_ButtonPressed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed_revoker consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ButtonPressed_revoker>(this, ButtonPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::ButtonPressed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->remove_ButtonPressed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->add_PropertyChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged_revoker consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PropertyChanged_revoker>(this, PropertyChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls<D>::PropertyChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls)->remove_PropertyChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaPlaybackAutoRepeatMode) consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatMode() const
    {
        winrt::Windows::Media::MediaPlaybackAutoRepeatMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->get_AutoRepeatMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatMode(winrt::Windows::Media::MediaPlaybackAutoRepeatMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->put_AutoRepeatMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->get_ShuffleEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->put_ShuffleEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->get_PlaybackRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRate(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->put_PlaybackRate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::UpdateTimelineProperties(winrt::Windows::Media::SystemMediaTransportControlsTimelineProperties const& timelineProperties) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->UpdateTimelineProperties(*(void**)(&timelineProperties)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::PlaybackPositionChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->add_PlaybackPositionChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::PlaybackPositionChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PlaybackPositionChangeRequested_revoker>(this, PlaybackPositionChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackPositionChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->remove_PlaybackPositionChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::PlaybackRateChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->add_PlaybackRateChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::PlaybackRateChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PlaybackRateChangeRequested_revoker>(this, PlaybackRateChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::PlaybackRateChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->remove_PlaybackRateChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::ShuffleEnabledChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->add_ShuffleEnabledChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::ShuffleEnabledChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ShuffleEnabledChangeRequested_revoker>(this, ShuffleEnabledChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::ShuffleEnabledChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->remove_ShuffleEnabledChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::AutoRepeatModeChangeRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->add_AutoRepeatModeChangeRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested_revoker consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::AutoRepeatModeChangeRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AutoRepeatModeChangeRequested_revoker>(this, AutoRepeatModeChangeRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControls2<D>::AutoRepeatModeChangeRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControls2)->remove_AutoRepeatModeChangeRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SystemMediaTransportControlsButton) consume_Windows_Media_ISystemMediaTransportControlsButtonPressedEventArgs<D>::Button() const
    {
        winrt::Windows::Media::SystemMediaTransportControlsButton value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs)->get_Button(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaPlaybackType) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Type() const
    {
        winrt::Windows::Media::MediaPlaybackType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Type(winrt::Windows::Media::MediaPlaybackType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->put_Type(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::AppMediaId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_AppMediaId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::AppMediaId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->put_AppMediaId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Thumbnail(winrt::Windows::Storage::Streams::RandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->put_Thumbnail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MusicDisplayProperties) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::MusicProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_MusicProperties(&value));
        return winrt::Windows::Media::MusicDisplayProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoDisplayProperties) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::VideoProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_VideoProperties(&value));
        return winrt::Windows::Media::VideoDisplayProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::ImageDisplayProperties) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::ImageProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->get_ImageProperties(&value));
        return winrt::Windows::Media::ImageDisplayProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::CopyFromFileAsync(winrt::Windows::Media::MediaPlaybackType const& type, winrt::Windows::Storage::StorageFile const& source) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->CopyFromFileAsync(static_cast<int32_t>(type), *(void**)(&source), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::ClearAll() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->ClearAll());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsDisplayUpdater<D>::Update() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater)->Update());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SystemMediaTransportControlsProperty) consume_Windows_Media_ISystemMediaTransportControlsPropertyChangedEventArgs<D>::Property() const
    {
        winrt::Windows::Media::SystemMediaTransportControlsProperty value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs)->get_Property(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SystemMediaTransportControls) consume_Windows_Media_ISystemMediaTransportControlsStatics<D>::GetForCurrentView() const
    {
        void* mediaControl{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsStatics)->GetForCurrentView(&mediaControl));
        return winrt::Windows::Media::SystemMediaTransportControls{ mediaControl, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::StartTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_StartTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::StartTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_StartTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::EndTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_EndTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::EndTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_EndTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MinSeekTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_MinSeekTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MinSeekTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_MinSeekTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MaxSeekTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_MaxSeekTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::MaxSeekTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_MaxSeekTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_ISystemMediaTransportControlsTimelineProperties<D>::Position(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IVideoDisplayProperties<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoDisplayProperties)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IVideoDisplayProperties<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoDisplayProperties)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IVideoDisplayProperties<D>::Subtitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoDisplayProperties)->get_Subtitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_IVideoDisplayProperties<D>::Subtitle(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoDisplayProperties)->put_Subtitle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Media_IVideoDisplayProperties2<D>::Genres() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoDisplayProperties2)->get_Genres(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_IVideoEffectsStatics<D>::VideoStabilization() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoEffectsStatics)->get_VideoStabilization(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::SoftwareBitmap) consume_Windows_Media_IVideoFrame<D>::SoftwareBitmap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrame)->get_SoftwareBitmap(&value));
        return winrt::Windows::Graphics::Imaging::SoftwareBitmap{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_IVideoFrame<D>::CopyToAsync(winrt::Windows::Media::VideoFrame const& frame) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrame)->CopyToAsync(*(void**)(&frame), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface) consume_Windows_Media_IVideoFrame<D>::Direct3DSurface() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrame)->get_Direct3DSurface(&value));
        return winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_IVideoFrame2<D>::CopyToAsync(winrt::Windows::Media::VideoFrame const& frame, winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::Imaging::BitmapBounds> const& sourceBounds, winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::Imaging::BitmapBounds> const& destinationBounds) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrame2)->CopyToWithBoundsAsync(*(void**)(&frame), *(void**)(&sourceBounds), *(void**)(&destinationBounds), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_IVideoFrameFactory<D>::Create(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrameFactory)->Create(static_cast<int32_t>(format), width, height, &value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_IVideoFrameFactory<D>::CreateWithAlpha(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, winrt::Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrameFactory)->CreateWithAlpha(static_cast<int32_t>(format), width, height, static_cast<int32_t>(alpha), &value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_IVideoFrameStatics<D>::CreateAsDirect3D11SurfaceBacked(winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrameStatics)->CreateAsDirect3D11SurfaceBacked(static_cast<int32_t>(format), width, height, &result));
        return winrt::Windows::Media::VideoFrame{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_IVideoFrameStatics<D>::CreateAsDirect3D11SurfaceBacked(winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrameStatics)->CreateAsDirect3D11SurfaceBackedWithDevice(static_cast<int32_t>(format), width, height, *(void**)(&device), &result));
        return winrt::Windows::Media::VideoFrame{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_IVideoFrameStatics<D>::CreateWithSoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrameStatics)->CreateWithSoftwareBitmap(*(void**)(&bitmap), &result));
        return winrt::Windows::Media::VideoFrame{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_IVideoFrameStatics<D>::CreateWithDirect3D11Surface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::IVideoFrameStatics)->CreateWithDirect3D11Surface(*(void**)(&surface), &result));
        return winrt::Windows::Media::VideoFrame{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IAudioBuffer> : produce_base<D, winrt::Windows::Media::IAudioBuffer>
    {
        int32_t __stdcall get_Capacity(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Capacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Length(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Length(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IAudioFrame> : produce_base<D, winrt::Windows::Media::IAudioFrame>
    {
        int32_t __stdcall LockBuffer(int32_t mode, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioBuffer>(this->shim().LockBuffer(*reinterpret_cast<winrt::Windows::Media::AudioBufferAccessMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IAudioFrameFactory> : produce_base<D, winrt::Windows::Media::IAudioFrameFactory>
    {
        int32_t __stdcall Create(uint32_t capacity, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioFrame>(this->shim().Create(capacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs>
    {
        int32_t __stdcall get_RequestedAutoRepeatMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaPlaybackAutoRepeatMode>(this->shim().RequestedAutoRepeatMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IImageDisplayProperties> : produce_base<D, winrt::Windows::Media::IImageDisplayProperties>
    {
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
        int32_t __stdcall get_Subtitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Subtitle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Subtitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaControl> : produce_base<D, winrt::Windows::Media::IMediaControl>
    {
        int32_t __stdcall add_SoundLevelChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().SoundLevelChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SoundLevelChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SoundLevelChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PlayPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PlayPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlayPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlayPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PausePressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PausePressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PausePressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PausePressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_StopPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StopPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StopPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PlayPauseTogglePressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PlayPauseTogglePressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlayPauseTogglePressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlayPauseTogglePressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_RecordPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().RecordPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecordPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecordPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_NextTrackPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().NextTrackPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NextTrackPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NextTrackPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PreviousTrackPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PreviousTrackPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PreviousTrackPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreviousTrackPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_FastForwardPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().FastForwardPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FastForwardPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FastForwardPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_RewindPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().RewindPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RewindPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RewindPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ChannelUpPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ChannelUpPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ChannelUpPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChannelUpPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ChannelDownPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().ChannelDownPressed(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ChannelDownPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChannelDownPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_SoundLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SoundLevel>(this->shim().SoundLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TrackName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TrackName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrackName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TrackName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ArtistName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ArtistName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ArtistName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ArtistName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPlaying(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPlaying(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlaying(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlaying());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AlbumArt(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlbumArt(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlbumArt(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().AlbumArt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaExtension> : produce_base<D, winrt::Windows::Media::IMediaExtension>
    {
        int32_t __stdcall SetProperties(void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetProperties(*reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaExtensionManager> : produce_base<D, winrt::Windows::Media::IMediaExtensionManager>
    {
        int32_t __stdcall RegisterSchemeHandler(void* activatableClassId, void* scheme) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterSchemeHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&scheme));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterSchemeHandlerWithSettings(void* activatableClassId, void* scheme, void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterSchemeHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&scheme), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterByteStreamHandler(void* activatableClassId, void* fileExtension, void* mimeType) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterByteStreamHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&fileExtension), *reinterpret_cast<hstring const*>(&mimeType));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterByteStreamHandlerWithSettings(void* activatableClassId, void* fileExtension, void* mimeType, void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterByteStreamHandler(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<hstring const*>(&fileExtension), *reinterpret_cast<hstring const*>(&mimeType), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterAudioDecoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterAudioDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterAudioDecoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterAudioDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterAudioEncoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterAudioEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterAudioEncoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterAudioEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterVideoDecoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterVideoDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterVideoDecoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterVideoDecoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterVideoEncoder(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterVideoEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterVideoEncoderWithSettings(void* activatableClassId, winrt::guid inputSubtype, winrt::guid outputSubtype, void* configuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterVideoEncoder(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::guid const*>(&inputSubtype), *reinterpret_cast<winrt::guid const*>(&outputSubtype), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaExtensionManager2> : produce_base<D, winrt::Windows::Media::IMediaExtensionManager2>
    {
        int32_t __stdcall RegisterMediaExtensionForAppService(void* extension, void* connection) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RegisterMediaExtensionForAppService(*reinterpret_cast<winrt::Windows::Media::IMediaExtension const*>(&extension), *reinterpret_cast<winrt::Windows::ApplicationModel::AppService::AppServiceConnection const*>(&connection));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaFrame> : produce_base<D, winrt::Windows::Media::IMediaFrame>
    {
        int32_t __stdcall get_Type(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReadOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelativeTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelativeTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelativeTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().RelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SystemRelativeTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemRelativeTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemRelativeTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().SystemRelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
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
        int32_t __stdcall put_IsDiscontinuous(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDiscontinuous(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDiscontinuous(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDiscontinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaMarker> : produce_base<D, winrt::Windows::Media::IMediaMarker>
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
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaMarkerTypesStatics> : produce_base<D, winrt::Windows::Media::IMediaMarkerTypesStatics>
    {
        int32_t __stdcall get_Bookmark(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Bookmark());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaMarkers> : produce_base<D, winrt::Windows::Media::IMediaMarkers>
    {
        int32_t __stdcall get_Markers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::IMediaMarker>>(this->shim().Markers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaProcessingTriggerDetails> : produce_base<D, winrt::Windows::Media::IMediaProcessingTriggerDetails>
    {
        int32_t __stdcall get_Arguments(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaTimelineController> : produce_base<D, winrt::Windows::Media::IMediaTimelineController>
    {
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Resume() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resume();
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
        int32_t __stdcall get_ClockRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ClockRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClockRate(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClockRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaTimelineControllerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PositionChanged(void* positionChangedEventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().PositionChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const*>(&positionChangedEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PositionChanged(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
        int32_t __stdcall add_StateChanged(void* stateChangedEventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const*>(&stateChangedEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaTimelineController2> : produce_base<D, winrt::Windows::Media::IMediaTimelineController2>
    {
        int32_t __stdcall get_Duration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
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
        int32_t __stdcall add_Failed(void* eventHandler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Failed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Media::MediaTimelineControllerFailedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Failed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Failed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Ended(void* eventHandler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Ended(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::MediaTimelineController, winrt::Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Ended(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Ended(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs> : produce_base<D, winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs>
    {
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
    struct produce<D, winrt::Windows::Media::IMusicDisplayProperties> : produce_base<D, winrt::Windows::Media::IMusicDisplayProperties>
    {
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
        int32_t __stdcall get_AlbumArtist(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AlbumArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AlbumArtist(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlbumArtist(*reinterpret_cast<hstring const*>(&value));
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
        int32_t __stdcall put_Artist(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Artist(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMusicDisplayProperties2> : produce_base<D, winrt::Windows::Media::IMusicDisplayProperties2>
    {
        int32_t __stdcall get_AlbumTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AlbumTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AlbumTitle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlbumTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrackNumber(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TrackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TrackNumber(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TrackNumber(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Genres(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().Genres());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IMusicDisplayProperties3> : produce_base<D, winrt::Windows::Media::IMusicDisplayProperties3>
    {
        int32_t __stdcall get_AlbumTrackCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AlbumTrackCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AlbumTrackCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlbumTrackCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs>
    {
        int32_t __stdcall get_RequestedPlaybackPosition(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().RequestedPlaybackPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs>
    {
        int32_t __stdcall get_RequestedPlaybackRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RequestedPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs> : produce_base<D, winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs>
    {
        int32_t __stdcall get_RequestedShuffleEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().RequestedShuffleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::ISystemMediaTransportControls> : produce_base<D, winrt::Windows::Media::ISystemMediaTransportControls>
    {
        int32_t __stdcall get_PlaybackStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaPlaybackStatus>(this->shim().PlaybackStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PlaybackStatus(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackStatus(*reinterpret_cast<winrt::Windows::Media::MediaPlaybackStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayUpdater(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SystemMediaTransportControlsDisplayUpdater>(this->shim().DisplayUpdater());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SoundLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SoundLevel>(this->shim().SoundLevel());
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
        int32_t __stdcall get_IsPlayEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlayEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPlayEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPlayEnabled(value);
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
        int32_t __stdcall put_IsStopEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsStopEnabled(value);
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
        int32_t __stdcall put_IsPauseEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPauseEnabled(value);
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
        int32_t __stdcall put_IsRecordEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsRecordEnabled(value);
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
        int32_t __stdcall put_IsFastForwardEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsFastForwardEnabled(value);
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
        int32_t __stdcall put_IsRewindEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsRewindEnabled(value);
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
        int32_t __stdcall put_IsPreviousEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPreviousEnabled(value);
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
        int32_t __stdcall put_IsNextEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsNextEnabled(value);
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
        int32_t __stdcall put_IsChannelUpEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsChannelUpEnabled(value);
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
        int32_t __stdcall put_IsChannelDownEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsChannelDownEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ButtonPressed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ButtonPressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ButtonPressed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ButtonPressed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PropertyChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PropertyChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PropertyChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PropertyChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::ISystemMediaTransportControls2> : produce_base<D, winrt::Windows::Media::ISystemMediaTransportControls2>
    {
        int32_t __stdcall get_AutoRepeatMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaPlaybackAutoRepeatMode>(this->shim().AutoRepeatMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoRepeatMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoRepeatMode(*reinterpret_cast<winrt::Windows::Media::MediaPlaybackAutoRepeatMode const*>(&value));
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
        int32_t __stdcall UpdateTimelineProperties(void* timelineProperties) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateTimelineProperties(*reinterpret_cast<winrt::Windows::Media::SystemMediaTransportControlsTimelineProperties const*>(&timelineProperties));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PlaybackPositionChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlaybackPositionChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::PlaybackPositionChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlaybackPositionChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackPositionChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PlaybackRateChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PlaybackRateChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::PlaybackRateChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PlaybackRateChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackRateChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ShuffleEnabledChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ShuffleEnabledChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::ShuffleEnabledChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ShuffleEnabledChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShuffleEnabledChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_AutoRepeatModeChangeRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AutoRepeatModeChangeRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SystemMediaTransportControls, winrt::Windows::Media::AutoRepeatModeChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AutoRepeatModeChangeRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoRepeatModeChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs> : produce_base<D, winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs>
    {
        int32_t __stdcall get_Button(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SystemMediaTransportControlsButton>(this->shim().Button());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater> : produce_base<D, winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater>
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
        int32_t __stdcall get_AppMediaId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppMediaId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppMediaId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppMediaId(*reinterpret_cast<hstring const*>(&value));
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
        int32_t __stdcall get_ImageProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::ImageDisplayProperties>(this->shim().ImageProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyFromFileAsync(int32_t type, void* source, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().CopyFromFileAsync(*reinterpret_cast<winrt::Windows::Media::MediaPlaybackType const*>(&type), *reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&source)));
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
        int32_t __stdcall Update() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Update();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs> : produce_base<D, winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs>
    {
        int32_t __stdcall get_Property(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SystemMediaTransportControlsProperty>(this->shim().Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::ISystemMediaTransportControlsStatics> : produce_base<D, winrt::Windows::Media::ISystemMediaTransportControlsStatics>
    {
        int32_t __stdcall GetForCurrentView(void** mediaControl) noexcept final try
        {
            clear_abi(mediaControl);
            typename D::abi_guard guard(this->shim());
            *mediaControl = detach_from<winrt::Windows::Media::SystemMediaTransportControls>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties> : produce_base<D, winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties>
    {
        int32_t __stdcall get_StartTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
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
        int32_t __stdcall put_EndTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
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
        int32_t __stdcall put_MinSeekTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinSeekTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
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
        int32_t __stdcall put_MaxSeekTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxSeekTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IVideoDisplayProperties> : produce_base<D, winrt::Windows::Media::IVideoDisplayProperties>
    {
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
        int32_t __stdcall get_Subtitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Subtitle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Subtitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IVideoDisplayProperties2> : produce_base<D, winrt::Windows::Media::IVideoDisplayProperties2>
    {
        int32_t __stdcall get_Genres(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().Genres());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IVideoEffectsStatics> : produce_base<D, winrt::Windows::Media::IVideoEffectsStatics>
    {
        int32_t __stdcall get_VideoStabilization(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoStabilization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IVideoFrame> : produce_base<D, winrt::Windows::Media::IVideoFrame>
    {
        int32_t __stdcall get_SoftwareBitmap(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().SoftwareBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyToAsync(void* frame, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CopyToAsync(*reinterpret_cast<winrt::Windows::Media::VideoFrame const*>(&frame)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Direct3DSurface(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Direct3DSurface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IVideoFrame2> : produce_base<D, winrt::Windows::Media::IVideoFrame2>
    {
        int32_t __stdcall CopyToWithBoundsAsync(void* frame, void* sourceBounds, void* destinationBounds, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CopyToAsync(*reinterpret_cast<winrt::Windows::Media::VideoFrame const*>(&frame), *reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::Imaging::BitmapBounds> const*>(&sourceBounds), *reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Graphics::Imaging::BitmapBounds> const*>(&destinationBounds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IVideoFrameFactory> : produce_base<D, winrt::Windows::Media::IVideoFrameFactory>
    {
        int32_t __stdcall Create(int32_t format, int32_t width, int32_t height, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().Create(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithAlpha(int32_t format, int32_t width, int32_t height, int32_t alpha, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().CreateWithAlpha(*reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height, *reinterpret_cast<winrt::Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::IVideoFrameStatics> : produce_base<D, winrt::Windows::Media::IVideoFrameStatics>
    {
        int32_t __stdcall CreateAsDirect3D11SurfaceBacked(int32_t format, int32_t width, int32_t height, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().CreateAsDirect3D11SurfaceBacked(*reinterpret_cast<winrt::Windows::Graphics::DirectX::DirectXPixelFormat const*>(&format), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAsDirect3D11SurfaceBackedWithDevice(int32_t format, int32_t width, int32_t height, void* device, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().CreateAsDirect3D11SurfaceBacked(*reinterpret_cast<winrt::Windows::Graphics::DirectX::DirectXPixelFormat const*>(&format), width, height, *reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithSoftwareBitmap(void* bitmap, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().CreateWithSoftwareBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithDirect3D11Surface(void* surface, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().CreateWithDirect3D11Surface(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media
{
    inline AudioFrame::AudioFrame(uint32_t capacity) :
        AudioFrame(impl::call_factory<AudioFrame, IAudioFrameFactory>([&](IAudioFrameFactory const& f) { return f.Create(capacity); }))
    {
    }
    inline auto MediaControl::SoundLevelChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.SoundLevelChanged(handler); });
    }
    inline MediaControl::SoundLevelChanged_revoker MediaControl::SoundLevelChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.SoundLevelChanged(handler) };
    }
    inline auto MediaControl::SoundLevelChanged(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.SoundLevelChanged(cookie); });
    }
    inline auto MediaControl::PlayPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PlayPressed(handler); });
    }
    inline MediaControl::PlayPressed_revoker MediaControl::PlayPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.PlayPressed(handler) };
    }
    inline auto MediaControl::PlayPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PlayPressed(cookie); });
    }
    inline auto MediaControl::PausePressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PausePressed(handler); });
    }
    inline MediaControl::PausePressed_revoker MediaControl::PausePressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.PausePressed(handler) };
    }
    inline auto MediaControl::PausePressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PausePressed(cookie); });
    }
    inline auto MediaControl::StopPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.StopPressed(handler); });
    }
    inline MediaControl::StopPressed_revoker MediaControl::StopPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.StopPressed(handler) };
    }
    inline auto MediaControl::StopPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.StopPressed(cookie); });
    }
    inline auto MediaControl::PlayPauseTogglePressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PlayPauseTogglePressed(handler); });
    }
    inline MediaControl::PlayPauseTogglePressed_revoker MediaControl::PlayPauseTogglePressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.PlayPauseTogglePressed(handler) };
    }
    inline auto MediaControl::PlayPauseTogglePressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PlayPauseTogglePressed(cookie); });
    }
    inline auto MediaControl::RecordPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.RecordPressed(handler); });
    }
    inline MediaControl::RecordPressed_revoker MediaControl::RecordPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.RecordPressed(handler) };
    }
    inline auto MediaControl::RecordPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.RecordPressed(cookie); });
    }
    inline auto MediaControl::NextTrackPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.NextTrackPressed(handler); });
    }
    inline MediaControl::NextTrackPressed_revoker MediaControl::NextTrackPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.NextTrackPressed(handler) };
    }
    inline auto MediaControl::NextTrackPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.NextTrackPressed(cookie); });
    }
    inline auto MediaControl::PreviousTrackPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PreviousTrackPressed(handler); });
    }
    inline MediaControl::PreviousTrackPressed_revoker MediaControl::PreviousTrackPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.PreviousTrackPressed(handler) };
    }
    inline auto MediaControl::PreviousTrackPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.PreviousTrackPressed(cookie); });
    }
    inline auto MediaControl::FastForwardPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.FastForwardPressed(handler); });
    }
    inline MediaControl::FastForwardPressed_revoker MediaControl::FastForwardPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.FastForwardPressed(handler) };
    }
    inline auto MediaControl::FastForwardPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.FastForwardPressed(cookie); });
    }
    inline auto MediaControl::RewindPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.RewindPressed(handler); });
    }
    inline MediaControl::RewindPressed_revoker MediaControl::RewindPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.RewindPressed(handler) };
    }
    inline auto MediaControl::RewindPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.RewindPressed(cookie); });
    }
    inline auto MediaControl::ChannelUpPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.ChannelUpPressed(handler); });
    }
    inline MediaControl::ChannelUpPressed_revoker MediaControl::ChannelUpPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.ChannelUpPressed(handler) };
    }
    inline auto MediaControl::ChannelUpPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.ChannelUpPressed(cookie); });
    }
    inline auto MediaControl::ChannelDownPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.ChannelDownPressed(handler); });
    }
    inline MediaControl::ChannelDownPressed_revoker MediaControl::ChannelDownPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<MediaControl, winrt::Windows::Media::IMediaControl>();
        return { f, f.ChannelDownPressed(handler) };
    }
    inline auto MediaControl::ChannelDownPressed(winrt::event_token const& cookie)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.ChannelDownPressed(cookie); });
    }
    inline auto MediaControl::SoundLevel()
    {
        return impl::call_factory_cast<winrt::Windows::Media::SoundLevel(*)(IMediaControl const&), MediaControl, IMediaControl>([](IMediaControl const& f) { return f.SoundLevel(); });
    }
    inline auto MediaControl::TrackName(param::hstring const& value)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.TrackName(value); });
    }
    inline auto MediaControl::TrackName()
    {
        return impl::call_factory_cast<hstring(*)(IMediaControl const&), MediaControl, IMediaControl>([](IMediaControl const& f) { return f.TrackName(); });
    }
    inline auto MediaControl::ArtistName(param::hstring const& value)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.ArtistName(value); });
    }
    inline auto MediaControl::ArtistName()
    {
        return impl::call_factory_cast<hstring(*)(IMediaControl const&), MediaControl, IMediaControl>([](IMediaControl const& f) { return f.ArtistName(); });
    }
    inline auto MediaControl::IsPlaying(bool value)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.IsPlaying(value); });
    }
    inline auto MediaControl::IsPlaying()
    {
        return impl::call_factory_cast<bool(*)(IMediaControl const&), MediaControl, IMediaControl>([](IMediaControl const& f) { return f.IsPlaying(); });
    }
    inline auto MediaControl::AlbumArt(winrt::Windows::Foundation::Uri const& value)
    {
        impl::call_factory<MediaControl, IMediaControl>([&](IMediaControl const& f) { return f.AlbumArt(value); });
    }
    inline auto MediaControl::AlbumArt()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Uri(*)(IMediaControl const&), MediaControl, IMediaControl>([](IMediaControl const& f) { return f.AlbumArt(); });
    }
    inline MediaExtensionManager::MediaExtensionManager() :
        MediaExtensionManager(impl::call_factory_cast<MediaExtensionManager(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaExtensionManager>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaExtensionManager>(); }))
    {
    }
    inline auto MediaMarkerTypes::Bookmark()
    {
        return impl::call_factory_cast<hstring(*)(IMediaMarkerTypesStatics const&), MediaMarkerTypes, IMediaMarkerTypesStatics>([](IMediaMarkerTypesStatics const& f) { return f.Bookmark(); });
    }
    inline MediaTimelineController::MediaTimelineController() :
        MediaTimelineController(impl::call_factory_cast<MediaTimelineController(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaTimelineController>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaTimelineController>(); }))
    {
    }
    inline auto SystemMediaTransportControls::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::Media::SystemMediaTransportControls(*)(ISystemMediaTransportControlsStatics const&), SystemMediaTransportControls, ISystemMediaTransportControlsStatics>([](ISystemMediaTransportControlsStatics const& f) { return f.GetForCurrentView(); });
    }
    inline SystemMediaTransportControlsTimelineProperties::SystemMediaTransportControlsTimelineProperties() :
        SystemMediaTransportControlsTimelineProperties(impl::call_factory_cast<SystemMediaTransportControlsTimelineProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), SystemMediaTransportControlsTimelineProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SystemMediaTransportControlsTimelineProperties>(); }))
    {
    }
    inline auto VideoEffects::VideoStabilization()
    {
        return impl::call_factory_cast<hstring(*)(IVideoEffectsStatics const&), VideoEffects, IVideoEffectsStatics>([](IVideoEffectsStatics const& f) { return f.VideoStabilization(); });
    }
    inline VideoFrame::VideoFrame(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) :
        VideoFrame(impl::call_factory<VideoFrame, IVideoFrameFactory>([&](IVideoFrameFactory const& f) { return f.Create(format, width, height); }))
    {
    }
    inline VideoFrame::VideoFrame(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, winrt::Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) :
        VideoFrame(impl::call_factory<VideoFrame, IVideoFrameFactory>([&](IVideoFrameFactory const& f) { return f.CreateWithAlpha(format, width, height, alpha); }))
    {
    }
    inline auto VideoFrame::CreateAsDirect3D11SurfaceBacked(winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height)
    {
        return impl::call_factory<VideoFrame, IVideoFrameStatics>([&](IVideoFrameStatics const& f) { return f.CreateAsDirect3D11SurfaceBacked(format, width, height); });
    }
    inline auto VideoFrame::CreateAsDirect3D11SurfaceBacked(winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device)
    {
        return impl::call_factory<VideoFrame, IVideoFrameStatics>([&](IVideoFrameStatics const& f) { return f.CreateAsDirect3D11SurfaceBacked(format, width, height, device); });
    }
    inline auto VideoFrame::CreateWithSoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& bitmap)
    {
        return impl::call_factory<VideoFrame, IVideoFrameStatics>([&](IVideoFrameStatics const& f) { return f.CreateWithSoftwareBitmap(bitmap); });
    }
    inline auto VideoFrame::CreateWithDirect3D11Surface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface)
    {
        return impl::call_factory<VideoFrame, IVideoFrameStatics>([&](IVideoFrameStatics const& f) { return f.CreateWithDirect3D11Surface(surface); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::IAudioBuffer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IAudioFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IAudioFrameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IImageDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaExtension> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaExtensionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaExtensionManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaMarker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaMarkerTypesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaMarkers> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaProcessingTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaTimelineController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaTimelineController2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMusicDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMusicDisplayProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IMusicDisplayProperties3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControls> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControls2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IVideoDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IVideoDisplayProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IVideoEffectsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IVideoFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IVideoFrame2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IVideoFrameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::IVideoFrameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AudioBuffer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AudioFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::AutoRepeatModeChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ImageDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaExtensionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaMarkerTypes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProcessingTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaTimelineController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaTimelineControllerFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MusicDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlaybackPositionChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::PlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::ShuffleEnabledChangeRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SystemMediaTransportControls> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsButtonPressedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsDisplayUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsPropertyChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SystemMediaTransportControlsTimelineProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::VideoDisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::VideoEffects> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::VideoFrame> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
