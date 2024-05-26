// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Core_1_H
#define WINRT_Windows_UI_Composition_Core_1_H
#include "winrt/impl/Windows.UI.Composition.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Core
{
    struct __declspec(empty_bases) ICompositorController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICompositorController>
    {
        ICompositorController(std::nullptr_t = nullptr) noexcept {}
        ICompositorController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
