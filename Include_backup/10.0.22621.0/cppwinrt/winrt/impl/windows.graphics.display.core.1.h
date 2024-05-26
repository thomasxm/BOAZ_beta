// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Display_Core_1_H
#define WINRT_Windows_Graphics_Display_Core_1_H
#include "winrt/impl/Windows.Graphics.Display.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Display::Core
{
    struct __declspec(empty_bases) IHdmiDisplayInformation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHdmiDisplayInformation>
    {
        IHdmiDisplayInformation(std::nullptr_t = nullptr) noexcept {}
        IHdmiDisplayInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHdmiDisplayInformationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHdmiDisplayInformationStatics>
    {
        IHdmiDisplayInformationStatics(std::nullptr_t = nullptr) noexcept {}
        IHdmiDisplayInformationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHdmiDisplayMode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHdmiDisplayMode>
    {
        IHdmiDisplayMode(std::nullptr_t = nullptr) noexcept {}
        IHdmiDisplayMode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHdmiDisplayMode2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHdmiDisplayMode2>
    {
        IHdmiDisplayMode2(std::nullptr_t = nullptr) noexcept {}
        IHdmiDisplayMode2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
