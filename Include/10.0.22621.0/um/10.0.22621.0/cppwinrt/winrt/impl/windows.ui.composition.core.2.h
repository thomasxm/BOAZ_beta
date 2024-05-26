// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Core_2_H
#define WINRT_Windows_UI_Composition_Core_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Composition.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Core
{
    struct __declspec(empty_bases) CompositorController : winrt::Windows::UI::Composition::Core::ICompositorController,
        impl::require<CompositorController, winrt::Windows::Foundation::IClosable>
    {
        CompositorController(std::nullptr_t) noexcept {}
        CompositorController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Composition::Core::ICompositorController(ptr, take_ownership_from_abi) {}
        CompositorController();
    };
}
#endif
