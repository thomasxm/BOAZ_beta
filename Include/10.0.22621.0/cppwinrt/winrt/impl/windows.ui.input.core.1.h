// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Core_1_H
#define WINRT_Windows_UI_Input_Core_1_H
#include "winrt/impl/Windows.UI.Input.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Core
{
    struct __declspec(empty_bases) IRadialControllerIndependentInputSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRadialControllerIndependentInputSource>
    {
        IRadialControllerIndependentInputSource(std::nullptr_t = nullptr) noexcept {}
        IRadialControllerIndependentInputSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRadialControllerIndependentInputSource2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRadialControllerIndependentInputSource2>
    {
        IRadialControllerIndependentInputSource2(std::nullptr_t = nullptr) noexcept {}
        IRadialControllerIndependentInputSource2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRadialControllerIndependentInputSourceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRadialControllerIndependentInputSourceStatics>
    {
        IRadialControllerIndependentInputSourceStatics(std::nullptr_t = nullptr) noexcept {}
        IRadialControllerIndependentInputSourceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
