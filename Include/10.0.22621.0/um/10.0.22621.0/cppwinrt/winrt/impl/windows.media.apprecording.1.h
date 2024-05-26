// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_AppRecording_1_H
#define WINRT_Windows_Media_AppRecording_1_H
#include "winrt/impl/Windows.Media.AppRecording.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::AppRecording
{
    struct __declspec(empty_bases) IAppRecordingManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppRecordingManager>
    {
        IAppRecordingManager(std::nullptr_t = nullptr) noexcept {}
        IAppRecordingManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppRecordingManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppRecordingManagerStatics>
    {
        IAppRecordingManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IAppRecordingManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppRecordingResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppRecordingResult>
    {
        IAppRecordingResult(std::nullptr_t = nullptr) noexcept {}
        IAppRecordingResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppRecordingSaveScreenshotResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppRecordingSaveScreenshotResult>
    {
        IAppRecordingSaveScreenshotResult(std::nullptr_t = nullptr) noexcept {}
        IAppRecordingSaveScreenshotResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppRecordingSavedScreenshotInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppRecordingSavedScreenshotInfo>
    {
        IAppRecordingSavedScreenshotInfo(std::nullptr_t = nullptr) noexcept {}
        IAppRecordingSavedScreenshotInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppRecordingStatus :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppRecordingStatus>
    {
        IAppRecordingStatus(std::nullptr_t = nullptr) noexcept {}
        IAppRecordingStatus(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppRecordingStatusDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppRecordingStatusDetails>
    {
        IAppRecordingStatusDetails(std::nullptr_t = nullptr) noexcept {}
        IAppRecordingStatusDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
