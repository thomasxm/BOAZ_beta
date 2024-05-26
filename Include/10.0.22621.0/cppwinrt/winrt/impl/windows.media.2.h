// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_2_H
#define WINRT_Windows_Media_2_H
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.1.h"
WINRT_EXPORT namespace winrt::Windows::Media
{
    struct MediaTimeRange
    {
        winrt::Windows::Foundation::TimeSpan Start;
        winrt::Windows::Foundation::TimeSpan End;
    };
    inline bool operator==(MediaTimeRange const& left, MediaTimeRange const& right) noexcept
    {
        return left.Start == right.Start && left.End == right.End;
    }
    inline bool operator!=(MediaTimeRange const& left, MediaTimeRange const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) AudioBuffer : winrt::Windows::Media::IAudioBuffer
    {
        AudioBuffer(std::nullptr_t) noexcept {}
        AudioBuffer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IAudioBuffer(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AudioFrame : winrt::Windows::Media::IAudioFrame
    {
        AudioFrame(std::nullptr_t) noexcept {}
        AudioFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IAudioFrame(ptr, take_ownership_from_abi) {}
        explicit AudioFrame(uint32_t capacity);
    };
    struct __declspec(empty_bases) AutoRepeatModeChangeRequestedEventArgs : winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs
    {
        AutoRepeatModeChangeRequestedEventArgs(std::nullptr_t) noexcept {}
        AutoRepeatModeChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IAutoRepeatModeChangeRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ImageDisplayProperties : winrt::Windows::Media::IImageDisplayProperties
    {
        ImageDisplayProperties(std::nullptr_t) noexcept {}
        ImageDisplayProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IImageDisplayProperties(ptr, take_ownership_from_abi) {}
    };
    struct MediaControl
    {
        MediaControl() = delete;
        static auto SoundLevelChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using SoundLevelChanged_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_SoundLevelChanged>;
        [[nodiscard]] static SoundLevelChanged_revoker SoundLevelChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto SoundLevelChanged(winrt::event_token const& cookie);
        static auto PlayPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using PlayPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_PlayPressed>;
        [[nodiscard]] static PlayPressed_revoker PlayPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto PlayPressed(winrt::event_token const& cookie);
        static auto PausePressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using PausePressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_PausePressed>;
        [[nodiscard]] static PausePressed_revoker PausePressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto PausePressed(winrt::event_token const& cookie);
        static auto StopPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using StopPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_StopPressed>;
        [[nodiscard]] static StopPressed_revoker StopPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto StopPressed(winrt::event_token const& cookie);
        static auto PlayPauseTogglePressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using PlayPauseTogglePressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_PlayPauseTogglePressed>;
        [[nodiscard]] static PlayPauseTogglePressed_revoker PlayPauseTogglePressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto PlayPauseTogglePressed(winrt::event_token const& cookie);
        static auto RecordPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RecordPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_RecordPressed>;
        [[nodiscard]] static RecordPressed_revoker RecordPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RecordPressed(winrt::event_token const& cookie);
        static auto NextTrackPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using NextTrackPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_NextTrackPressed>;
        [[nodiscard]] static NextTrackPressed_revoker NextTrackPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto NextTrackPressed(winrt::event_token const& cookie);
        static auto PreviousTrackPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using PreviousTrackPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_PreviousTrackPressed>;
        [[nodiscard]] static PreviousTrackPressed_revoker PreviousTrackPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto PreviousTrackPressed(winrt::event_token const& cookie);
        static auto FastForwardPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using FastForwardPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_FastForwardPressed>;
        [[nodiscard]] static FastForwardPressed_revoker FastForwardPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto FastForwardPressed(winrt::event_token const& cookie);
        static auto RewindPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using RewindPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_RewindPressed>;
        [[nodiscard]] static RewindPressed_revoker RewindPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto RewindPressed(winrt::event_token const& cookie);
        static auto ChannelUpPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using ChannelUpPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_ChannelUpPressed>;
        [[nodiscard]] static ChannelUpPressed_revoker ChannelUpPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto ChannelUpPressed(winrt::event_token const& cookie);
        static auto ChannelDownPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using ChannelDownPressed_revoker = impl::factory_event_revoker<winrt::Windows::Media::IMediaControl, &impl::abi_t<winrt::Windows::Media::IMediaControl>::remove_ChannelDownPressed>;
        [[nodiscard]] static ChannelDownPressed_revoker ChannelDownPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto ChannelDownPressed(winrt::event_token const& cookie);
        [[nodiscard]] static auto SoundLevel();
        static auto TrackName(param::hstring const& value);
        [[nodiscard]] static auto TrackName();
        static auto ArtistName(param::hstring const& value);
        [[nodiscard]] static auto ArtistName();
        static auto IsPlaying(bool value);
        [[nodiscard]] static auto IsPlaying();
        static auto AlbumArt(winrt::Windows::Foundation::Uri const& value);
        [[nodiscard]] static auto AlbumArt();
    };
    struct __declspec(empty_bases) MediaExtensionManager : winrt::Windows::Media::IMediaExtensionManager,
        impl::require<MediaExtensionManager, winrt::Windows::Media::IMediaExtensionManager2>
    {
        MediaExtensionManager(std::nullptr_t) noexcept {}
        MediaExtensionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IMediaExtensionManager(ptr, take_ownership_from_abi) {}
        MediaExtensionManager();
    };
    struct MediaMarkerTypes
    {
        MediaMarkerTypes() = delete;
        [[nodiscard]] static auto Bookmark();
    };
    struct __declspec(empty_bases) MediaProcessingTriggerDetails : winrt::Windows::Media::IMediaProcessingTriggerDetails
    {
        MediaProcessingTriggerDetails(std::nullptr_t) noexcept {}
        MediaProcessingTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IMediaProcessingTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaTimelineController : winrt::Windows::Media::IMediaTimelineController,
        impl::require<MediaTimelineController, winrt::Windows::Media::IMediaTimelineController2>
    {
        MediaTimelineController(std::nullptr_t) noexcept {}
        MediaTimelineController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IMediaTimelineController(ptr, take_ownership_from_abi) {}
        MediaTimelineController();
    };
    struct __declspec(empty_bases) MediaTimelineControllerFailedEventArgs : winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs
    {
        MediaTimelineControllerFailedEventArgs(std::nullptr_t) noexcept {}
        MediaTimelineControllerFailedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IMediaTimelineControllerFailedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MusicDisplayProperties : winrt::Windows::Media::IMusicDisplayProperties,
        impl::require<MusicDisplayProperties, winrt::Windows::Media::IMusicDisplayProperties2, winrt::Windows::Media::IMusicDisplayProperties3>
    {
        MusicDisplayProperties(std::nullptr_t) noexcept {}
        MusicDisplayProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IMusicDisplayProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PlaybackPositionChangeRequestedEventArgs : winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs
    {
        PlaybackPositionChangeRequestedEventArgs(std::nullptr_t) noexcept {}
        PlaybackPositionChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IPlaybackPositionChangeRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PlaybackRateChangeRequestedEventArgs : winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs
    {
        PlaybackRateChangeRequestedEventArgs(std::nullptr_t) noexcept {}
        PlaybackRateChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IPlaybackRateChangeRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShuffleEnabledChangeRequestedEventArgs : winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs
    {
        ShuffleEnabledChangeRequestedEventArgs(std::nullptr_t) noexcept {}
        ShuffleEnabledChangeRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IShuffleEnabledChangeRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemMediaTransportControls : winrt::Windows::Media::ISystemMediaTransportControls,
        impl::require<SystemMediaTransportControls, winrt::Windows::Media::ISystemMediaTransportControls2>
    {
        SystemMediaTransportControls(std::nullptr_t) noexcept {}
        SystemMediaTransportControls(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ISystemMediaTransportControls(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
    struct __declspec(empty_bases) SystemMediaTransportControlsButtonPressedEventArgs : winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs
    {
        SystemMediaTransportControlsButtonPressedEventArgs(std::nullptr_t) noexcept {}
        SystemMediaTransportControlsButtonPressedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemMediaTransportControlsDisplayUpdater : winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater
    {
        SystemMediaTransportControlsDisplayUpdater(std::nullptr_t) noexcept {}
        SystemMediaTransportControlsDisplayUpdater(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ISystemMediaTransportControlsDisplayUpdater(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemMediaTransportControlsPropertyChangedEventArgs : winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs
    {
        SystemMediaTransportControlsPropertyChangedEventArgs(std::nullptr_t) noexcept {}
        SystemMediaTransportControlsPropertyChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemMediaTransportControlsTimelineProperties : winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties
    {
        SystemMediaTransportControlsTimelineProperties(std::nullptr_t) noexcept {}
        SystemMediaTransportControlsTimelineProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::ISystemMediaTransportControlsTimelineProperties(ptr, take_ownership_from_abi) {}
        SystemMediaTransportControlsTimelineProperties();
    };
    struct __declspec(empty_bases) VideoDisplayProperties : winrt::Windows::Media::IVideoDisplayProperties,
        impl::require<VideoDisplayProperties, winrt::Windows::Media::IVideoDisplayProperties2>
    {
        VideoDisplayProperties(std::nullptr_t) noexcept {}
        VideoDisplayProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IVideoDisplayProperties(ptr, take_ownership_from_abi) {}
    };
    struct VideoEffects
    {
        VideoEffects() = delete;
        [[nodiscard]] static auto VideoStabilization();
    };
    struct __declspec(empty_bases) VideoFrame : winrt::Windows::Media::IVideoFrame,
        impl::require<VideoFrame, winrt::Windows::Media::IVideoFrame2>
    {
        VideoFrame(std::nullptr_t) noexcept {}
        VideoFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::IVideoFrame(ptr, take_ownership_from_abi) {}
        VideoFrame(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height);
        VideoFrame(winrt::Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, winrt::Windows::Graphics::Imaging::BitmapAlphaMode const& alpha);
        using winrt::Windows::Media::IVideoFrame::CopyToAsync;
        using impl::consume_t<VideoFrame, winrt::Windows::Media::IVideoFrame2>::CopyToAsync;
        static auto CreateAsDirect3D11SurfaceBacked(winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height);
        static auto CreateAsDirect3D11SurfaceBacked(winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device);
        static auto CreateWithSoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& bitmap);
        static auto CreateWithDirect3D11Surface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface);
    };
}
#endif
