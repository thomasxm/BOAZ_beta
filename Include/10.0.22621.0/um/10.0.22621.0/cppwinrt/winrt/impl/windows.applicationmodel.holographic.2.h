// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Holographic_2_H
#define WINRT_Windows_ApplicationModel_Holographic_2_H
#include "winrt/impl/Windows.ApplicationModel.Holographic.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Holographic
{
    struct __declspec(empty_bases) HolographicKeyboard : winrt::Windows::ApplicationModel::Holographic::IHolographicKeyboard
    {
        HolographicKeyboard(std::nullptr_t) noexcept {}
        HolographicKeyboard(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Holographic::IHolographicKeyboard(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
    };
}
#endif
