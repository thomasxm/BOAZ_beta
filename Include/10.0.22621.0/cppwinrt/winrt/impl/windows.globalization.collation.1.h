// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_Collation_1_H
#define WINRT_Windows_Globalization_Collation_1_H
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Globalization.Collation.0.h"
WINRT_EXPORT namespace winrt::Windows::Globalization::Collation
{
    struct __declspec(empty_bases) ICharacterGrouping :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICharacterGrouping>
    {
        ICharacterGrouping(std::nullptr_t = nullptr) noexcept {}
        ICharacterGrouping(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICharacterGroupings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICharacterGroupings>,
        impl::require<winrt::Windows::Globalization::Collation::ICharacterGroupings, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Globalization::Collation::CharacterGrouping>, winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Collation::CharacterGrouping>>
    {
        ICharacterGroupings(std::nullptr_t = nullptr) noexcept {}
        ICharacterGroupings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICharacterGroupingsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICharacterGroupingsFactory>
    {
        ICharacterGroupingsFactory(std::nullptr_t = nullptr) noexcept {}
        ICharacterGroupingsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
