// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Input_Preview_1_H
#define WINRT_Windows_Devices_Input_Preview_1_H
#include "winrt/impl/Windows.Devices.Input.Preview.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Input::Preview
{
    struct __declspec(empty_bases) IGazeDevicePreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeDevicePreview>
    {
        IGazeDevicePreview(std::nullptr_t = nullptr) noexcept {}
        IGazeDevicePreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeDeviceWatcherAddedPreviewEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeDeviceWatcherAddedPreviewEventArgs>
    {
        IGazeDeviceWatcherAddedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGazeDeviceWatcherAddedPreviewEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeDeviceWatcherPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeDeviceWatcherPreview>
    {
        IGazeDeviceWatcherPreview(std::nullptr_t = nullptr) noexcept {}
        IGazeDeviceWatcherPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeDeviceWatcherRemovedPreviewEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeDeviceWatcherRemovedPreviewEventArgs>
    {
        IGazeDeviceWatcherRemovedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGazeDeviceWatcherRemovedPreviewEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeDeviceWatcherUpdatedPreviewEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeDeviceWatcherUpdatedPreviewEventArgs>
    {
        IGazeDeviceWatcherUpdatedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGazeDeviceWatcherUpdatedPreviewEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeEnteredPreviewEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeEnteredPreviewEventArgs>
    {
        IGazeEnteredPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGazeEnteredPreviewEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeExitedPreviewEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeExitedPreviewEventArgs>
    {
        IGazeExitedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGazeExitedPreviewEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeInputSourcePreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeInputSourcePreview>
    {
        IGazeInputSourcePreview(std::nullptr_t = nullptr) noexcept {}
        IGazeInputSourcePreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeInputSourcePreviewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeInputSourcePreviewStatics>
    {
        IGazeInputSourcePreviewStatics(std::nullptr_t = nullptr) noexcept {}
        IGazeInputSourcePreviewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazeMovedPreviewEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazeMovedPreviewEventArgs>
    {
        IGazeMovedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
        IGazeMovedPreviewEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGazePointPreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGazePointPreview>
    {
        IGazePointPreview(std::nullptr_t = nullptr) noexcept {}
        IGazePointPreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
