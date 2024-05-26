// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Preview_Holographic_1_H
#define WINRT_Windows_ApplicationModel_Preview_Holographic_1_H
#include "winrt/impl/Windows.ApplicationModel.Preview.Holographic.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic
{
    struct __declspec(empty_bases) IHolographicApplicationPreviewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicApplicationPreviewStatics>
    {
        IHolographicApplicationPreviewStatics(std::nullptr_t = nullptr) noexcept {}
        IHolographicApplicationPreviewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicKeyboardPlacementOverridePreview :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicKeyboardPlacementOverridePreview>
    {
        IHolographicKeyboardPlacementOverridePreview(std::nullptr_t = nullptr) noexcept {}
        IHolographicKeyboardPlacementOverridePreview(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicKeyboardPlacementOverridePreviewStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicKeyboardPlacementOverridePreviewStatics>
    {
        IHolographicKeyboardPlacementOverridePreviewStatics(std::nullptr_t = nullptr) noexcept {}
        IHolographicKeyboardPlacementOverridePreviewStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
