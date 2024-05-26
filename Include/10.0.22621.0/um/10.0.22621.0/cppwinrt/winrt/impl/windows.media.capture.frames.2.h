// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Capture_Frames_2_H
#define WINRT_Windows_Media_Capture_Frames_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Media.Capture.Frames.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::Capture::Frames
{
    struct __declspec(empty_bases) AudioMediaFrame : winrt::Windows::Media::Capture::Frames::IAudioMediaFrame
    {
        AudioMediaFrame(std::nullptr_t) noexcept {}
        AudioMediaFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IAudioMediaFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) BufferMediaFrame : winrt::Windows::Media::Capture::Frames::IBufferMediaFrame
    {
        BufferMediaFrame(std::nullptr_t) noexcept {}
        BufferMediaFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IBufferMediaFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DepthMediaFrame : winrt::Windows::Media::Capture::Frames::IDepthMediaFrame,
        impl::require<DepthMediaFrame, winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2>
    {
        DepthMediaFrame(std::nullptr_t) noexcept {}
        DepthMediaFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IDepthMediaFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DepthMediaFrameFormat : winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat
    {
        DepthMediaFrameFormat(std::nullptr_t) noexcept {}
        DepthMediaFrameFormat(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InfraredMediaFrame : winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame
    {
        InfraredMediaFrame(std::nullptr_t) noexcept {}
        InfraredMediaFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameArrivedEventArgs : winrt::Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs
    {
        MediaFrameArrivedEventArgs(std::nullptr_t) noexcept {}
        MediaFrameArrivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameFormat : winrt::Windows::Media::Capture::Frames::IMediaFrameFormat,
        impl::require<MediaFrameFormat, winrt::Windows::Media::Capture::Frames::IMediaFrameFormat2>
    {
        MediaFrameFormat(std::nullptr_t) noexcept {}
        MediaFrameFormat(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameFormat(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameReader : winrt::Windows::Media::Capture::Frames::IMediaFrameReader,
        impl::require<MediaFrameReader, winrt::Windows::Media::Capture::Frames::IMediaFrameReader2>
    {
        MediaFrameReader(std::nullptr_t) noexcept {}
        MediaFrameReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameReader(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameReference : winrt::Windows::Media::Capture::Frames::IMediaFrameReference,
        impl::require<MediaFrameReference, winrt::Windows::Media::Capture::Frames::IMediaFrameReference2>
    {
        MediaFrameReference(std::nullptr_t) noexcept {}
        MediaFrameReference(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameReference(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameSource : winrt::Windows::Media::Capture::Frames::IMediaFrameSource
    {
        MediaFrameSource(std::nullptr_t) noexcept {}
        MediaFrameSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameSource(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameSourceController : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController,
        impl::require<MediaFrameSourceController, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController3>
    {
        MediaFrameSourceController(std::nullptr_t) noexcept {}
        MediaFrameSourceController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameSourceGetPropertyResult : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult
    {
        MediaFrameSourceGetPropertyResult(std::nullptr_t) noexcept {}
        MediaFrameSourceGetPropertyResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MediaFrameSourceGroup : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup
    {
        MediaFrameSourceGroup(std::nullptr_t) noexcept {}
        MediaFrameSourceGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup(ptr, take_ownership_from_abi) {}
        static auto FindAllAsync();
        static auto FromIdAsync(param::hstring const& id);
        static auto GetDeviceSelector();
    };
    struct __declspec(empty_bases) MediaFrameSourceInfo : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo,
        impl::require<MediaFrameSourceInfo, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo3, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo4>
    {
        MediaFrameSourceInfo(std::nullptr_t) noexcept {}
        MediaFrameSourceInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MultiSourceMediaFrameArrivedEventArgs : winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs
    {
        MultiSourceMediaFrameArrivedEventArgs(std::nullptr_t) noexcept {}
        MultiSourceMediaFrameArrivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MultiSourceMediaFrameReader : winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader,
        impl::require<MultiSourceMediaFrameReader, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2>
    {
        MultiSourceMediaFrameReader(std::nullptr_t) noexcept {}
        MultiSourceMediaFrameReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MultiSourceMediaFrameReference : winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference
    {
        MultiSourceMediaFrameReference(std::nullptr_t) noexcept {}
        MultiSourceMediaFrameReference(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VideoMediaFrame : winrt::Windows::Media::Capture::Frames::IVideoMediaFrame
    {
        VideoMediaFrame(std::nullptr_t) noexcept {}
        VideoMediaFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IVideoMediaFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VideoMediaFrameFormat : winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat
    {
        VideoMediaFrameFormat(std::nullptr_t) noexcept {}
        VideoMediaFrameFormat(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat(ptr, take_ownership_from_abi) {}
    };
}
#endif
