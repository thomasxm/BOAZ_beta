// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Scanners_2_H
#define WINRT_Windows_Devices_Scanners_2_H
#include "winrt/impl/Windows.Devices.Scanners.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Scanners
{
    struct ImageScannerResolution
    {
        float DpiX;
        float DpiY;
    };
    inline bool operator==(ImageScannerResolution const& left, ImageScannerResolution const& right) noexcept
    {
        return left.DpiX == right.DpiX && left.DpiY == right.DpiY;
    }
    inline bool operator!=(ImageScannerResolution const& left, ImageScannerResolution const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) ImageScanner : winrt::Windows::Devices::Scanners::IImageScanner
    {
        ImageScanner(std::nullptr_t) noexcept {}
        ImageScanner(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Scanners::IImageScanner(ptr, take_ownership_from_abi) {}
        static auto FromIdAsync(param::hstring const& deviceId);
        static auto GetDeviceSelector();
    };
    struct __declspec(empty_bases) ImageScannerAutoConfiguration : winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration
    {
        ImageScannerAutoConfiguration(std::nullptr_t) noexcept {}
        ImageScannerAutoConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ImageScannerFeederConfiguration : winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration,
        impl::require<ImageScannerFeederConfiguration, winrt::Windows::Devices::Scanners::IImageScannerSourceConfiguration, winrt::Windows::Devices::Scanners::IImageScannerFeederConfiguration>
    {
        ImageScannerFeederConfiguration(std::nullptr_t) noexcept {}
        ImageScannerFeederConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ImageScannerFlatbedConfiguration : winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration,
        impl::require<ImageScannerFlatbedConfiguration, winrt::Windows::Devices::Scanners::IImageScannerSourceConfiguration>
    {
        ImageScannerFlatbedConfiguration(std::nullptr_t) noexcept {}
        ImageScannerFlatbedConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ImageScannerPreviewResult : winrt::Windows::Devices::Scanners::IImageScannerPreviewResult
    {
        ImageScannerPreviewResult(std::nullptr_t) noexcept {}
        ImageScannerPreviewResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Scanners::IImageScannerPreviewResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ImageScannerScanResult : winrt::Windows::Devices::Scanners::IImageScannerScanResult
    {
        ImageScannerScanResult(std::nullptr_t) noexcept {}
        ImageScannerScanResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Scanners::IImageScannerScanResult(ptr, take_ownership_from_abi) {}
    };
}
#endif
