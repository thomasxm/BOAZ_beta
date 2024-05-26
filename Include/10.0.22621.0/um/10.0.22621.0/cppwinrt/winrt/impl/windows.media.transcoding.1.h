// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Transcoding_1_H
#define WINRT_Windows_Media_Transcoding_1_H
#include "winrt/impl/Windows.Media.Transcoding.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::Transcoding
{
    struct __declspec(empty_bases) IMediaTranscoder :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMediaTranscoder>
    {
        IMediaTranscoder(std::nullptr_t = nullptr) noexcept {}
        IMediaTranscoder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMediaTranscoder2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMediaTranscoder2>
    {
        IMediaTranscoder2(std::nullptr_t = nullptr) noexcept {}
        IMediaTranscoder2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrepareTranscodeResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrepareTranscodeResult>
    {
        IPrepareTranscodeResult(std::nullptr_t = nullptr) noexcept {}
        IPrepareTranscodeResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
