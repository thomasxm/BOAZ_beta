// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Radios_1_H
#define WINRT_Windows_Devices_Radios_1_H
#include "winrt/impl/Windows.Devices.Radios.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Radios
{
    struct __declspec(empty_bases) IRadio :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRadio>
    {
        IRadio(std::nullptr_t = nullptr) noexcept {}
        IRadio(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRadioStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRadioStatics>
    {
        IRadioStatics(std::nullptr_t = nullptr) noexcept {}
        IRadioStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
