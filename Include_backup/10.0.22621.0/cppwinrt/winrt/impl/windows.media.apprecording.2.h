// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_AppRecording_2_H
#define WINRT_Windows_Media_AppRecording_2_H
#include "winrt/impl/Windows.Media.AppRecording.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::AppRecording
{
    struct __declspec(empty_bases) AppRecordingManager : winrt::Windows::Media::AppRecording::IAppRecordingManager
    {
        AppRecordingManager(std::nullptr_t) noexcept {}
        AppRecordingManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppRecording::IAppRecordingManager(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
    };
    struct __declspec(empty_bases) AppRecordingResult : winrt::Windows::Media::AppRecording::IAppRecordingResult
    {
        AppRecordingResult(std::nullptr_t) noexcept {}
        AppRecordingResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppRecording::IAppRecordingResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppRecordingSaveScreenshotResult : winrt::Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult
    {
        AppRecordingSaveScreenshotResult(std::nullptr_t) noexcept {}
        AppRecordingSaveScreenshotResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppRecording::IAppRecordingSaveScreenshotResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppRecordingSavedScreenshotInfo : winrt::Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo
    {
        AppRecordingSavedScreenshotInfo(std::nullptr_t) noexcept {}
        AppRecordingSavedScreenshotInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppRecording::IAppRecordingSavedScreenshotInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppRecordingStatus : winrt::Windows::Media::AppRecording::IAppRecordingStatus
    {
        AppRecordingStatus(std::nullptr_t) noexcept {}
        AppRecordingStatus(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppRecording::IAppRecordingStatus(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppRecordingStatusDetails : winrt::Windows::Media::AppRecording::IAppRecordingStatusDetails
    {
        AppRecordingStatusDetails(std::nullptr_t) noexcept {}
        AppRecordingStatusDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::AppRecording::IAppRecordingStatusDetails(ptr, take_ownership_from_abi) {}
    };
}
#endif
