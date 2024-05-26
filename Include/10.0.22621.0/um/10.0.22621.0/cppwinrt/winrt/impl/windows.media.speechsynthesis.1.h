// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_SpeechSynthesis_1_H
#define WINRT_Windows_Media_SpeechSynthesis_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Media.SpeechSynthesis.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::SpeechSynthesis
{
    struct __declspec(empty_bases) IInstalledVoicesStatic :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInstalledVoicesStatic>
    {
        IInstalledVoicesStatic(std::nullptr_t = nullptr) noexcept {}
        IInstalledVoicesStatic(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInstalledVoicesStatic2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInstalledVoicesStatic2>
    {
        IInstalledVoicesStatic2(std::nullptr_t = nullptr) noexcept {}
        IInstalledVoicesStatic2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpeechSynthesisStream :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpeechSynthesisStream>,
        impl::require<winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesisStream, winrt::Windows::Foundation::IClosable, winrt::Windows::Storage::Streams::IInputStream, winrt::Windows::Storage::Streams::IOutputStream, winrt::Windows::Storage::Streams::IRandomAccessStream, winrt::Windows::Storage::Streams::IContentTypeProvider, winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>
    {
        ISpeechSynthesisStream(std::nullptr_t = nullptr) noexcept {}
        ISpeechSynthesisStream(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpeechSynthesizer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpeechSynthesizer>
    {
        ISpeechSynthesizer(std::nullptr_t = nullptr) noexcept {}
        ISpeechSynthesizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpeechSynthesizer2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpeechSynthesizer2>
    {
        ISpeechSynthesizer2(std::nullptr_t = nullptr) noexcept {}
        ISpeechSynthesizer2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpeechSynthesizerOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpeechSynthesizerOptions>
    {
        ISpeechSynthesizerOptions(std::nullptr_t = nullptr) noexcept {}
        ISpeechSynthesizerOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpeechSynthesizerOptions2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpeechSynthesizerOptions2>
    {
        ISpeechSynthesizerOptions2(std::nullptr_t = nullptr) noexcept {}
        ISpeechSynthesizerOptions2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpeechSynthesizerOptions3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpeechSynthesizerOptions3>
    {
        ISpeechSynthesizerOptions3(std::nullptr_t = nullptr) noexcept {}
        ISpeechSynthesizerOptions3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoiceInformation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoiceInformation>
    {
        IVoiceInformation(std::nullptr_t = nullptr) noexcept {}
        IVoiceInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
