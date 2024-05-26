// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Scanners_1_H
#define WINRT_Windows_Devices_Scanners_1_H
#include "winrt/impl/Windows.Devices.Scanners.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Scanners
{
    struct __declspec(empty_bases) IImageScanner :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageScanner>
    {
        IImageScanner(std::nullptr_t = nullptr) noexcept {}
        IImageScanner(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IImageScannerFeederConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageScannerFeederConfiguration>,
        impl::require<winrt::Windows::Devices::Scanners::IImageScannerFeederConfiguration, winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration, winrt::Windows::Devices::Scanners::IImageScannerSourceConfiguration>
    {
        IImageScannerFeederConfiguration(std::nullptr_t = nullptr) noexcept {}
        IImageScannerFeederConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IImageScannerFormatConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageScannerFormatConfiguration>
    {
        IImageScannerFormatConfiguration(std::nullptr_t = nullptr) noexcept {}
        IImageScannerFormatConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IImageScannerPreviewResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageScannerPreviewResult>
    {
        IImageScannerPreviewResult(std::nullptr_t = nullptr) noexcept {}
        IImageScannerPreviewResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IImageScannerScanResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageScannerScanResult>
    {
        IImageScannerScanResult(std::nullptr_t = nullptr) noexcept {}
        IImageScannerScanResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IImageScannerSourceConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageScannerSourceConfiguration>,
        impl::require<winrt::Windows::Devices::Scanners::IImageScannerSourceConfiguration, winrt::Windows::Devices::Scanners::IImageScannerFormatConfiguration>
    {
        IImageScannerSourceConfiguration(std::nullptr_t = nullptr) noexcept {}
        IImageScannerSourceConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IImageScannerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IImageScannerStatics>
    {
        IImageScannerStatics(std::nullptr_t = nullptr) noexcept {}
        IImageScannerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
