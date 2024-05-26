// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Preview_2_H
#define WINRT_Windows_System_Preview_2_H
#include "winrt/impl/Windows.System.Preview.1.h"
WINRT_EXPORT namespace winrt::Windows::System::Preview
{
    struct __declspec(empty_bases) TwoPanelHingedDevicePosturePreview : winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview
    {
        TwoPanelHingedDevicePosturePreview(std::nullptr_t) noexcept {}
        TwoPanelHingedDevicePosturePreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreview(ptr, take_ownership_from_abi) {}
        static auto GetDefaultAsync();
    };
    struct __declspec(empty_bases) TwoPanelHingedDevicePosturePreviewReading : winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading
    {
        TwoPanelHingedDevicePosturePreviewReading(std::nullptr_t) noexcept {}
        TwoPanelHingedDevicePosturePreviewReading(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReading(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs : winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs
    {
        TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs(std::nullptr_t) noexcept {}
        TwoPanelHingedDevicePosturePreviewReadingChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Preview::ITwoPanelHingedDevicePosturePreviewReadingChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
