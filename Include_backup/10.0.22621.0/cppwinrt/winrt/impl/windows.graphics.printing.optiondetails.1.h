// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Printing_OptionDetails_1_H
#define WINRT_Windows_Graphics_Printing_OptionDetails_1_H
#include "winrt/impl/Windows.Graphics.Printing.OptionDetails.0.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::OptionDetails
{
    struct __declspec(empty_bases) IPrintBindingOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintBindingOptionDetails>
    {
        IPrintBindingOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintBindingOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintBorderingOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintBorderingOptionDetails>
    {
        IPrintBorderingOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintBorderingOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCollationOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCollationOptionDetails>
    {
        IPrintCollationOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintCollationOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintColorModeOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintColorModeOptionDetails>
    {
        IPrintColorModeOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintColorModeOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCopiesOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCopiesOptionDetails>
    {
        IPrintCopiesOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintCopiesOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomItemDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomItemDetails>
    {
        IPrintCustomItemDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomItemDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomItemListOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomItemListOptionDetails>,
        impl::require<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomItemListOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails>
    {
        IPrintCustomItemListOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomItemListOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomItemListOptionDetails2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomItemListOptionDetails2>
    {
        IPrintCustomItemListOptionDetails2(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomItemListOptionDetails2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomItemListOptionDetails3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomItemListOptionDetails3>
    {
        IPrintCustomItemListOptionDetails3(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomItemListOptionDetails3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomOptionDetails>,
        impl::require<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
    {
        IPrintCustomOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomTextOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomTextOptionDetails>,
        impl::require<winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomTextOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintCustomOptionDetails>
    {
        IPrintCustomTextOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomTextOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomTextOptionDetails2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomTextOptionDetails2>
    {
        IPrintCustomTextOptionDetails2(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomTextOptionDetails2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintCustomToggleOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintCustomToggleOptionDetails>
    {
        IPrintCustomToggleOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintCustomToggleOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintDuplexOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintDuplexOptionDetails>
    {
        IPrintDuplexOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintDuplexOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintHolePunchOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintHolePunchOptionDetails>
    {
        IPrintHolePunchOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintHolePunchOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintItemListOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintItemListOptionDetails>,
        impl::require<winrt::Windows::Graphics::Printing::OptionDetails::IPrintItemListOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
    {
        IPrintItemListOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintItemListOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintMediaSizeOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintMediaSizeOptionDetails>
    {
        IPrintMediaSizeOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintMediaSizeOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintMediaTypeOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintMediaTypeOptionDetails>
    {
        IPrintMediaTypeOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintMediaTypeOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintNumberOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintNumberOptionDetails>,
        impl::require<winrt::Windows::Graphics::Printing::OptionDetails::IPrintNumberOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
    {
        IPrintNumberOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintNumberOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintOptionDetails>
    {
        IPrintOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintOrientationOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintOrientationOptionDetails>
    {
        IPrintOrientationOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintOrientationOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintPageRangeOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintPageRangeOptionDetails>
    {
        IPrintPageRangeOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintPageRangeOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintQualityOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintQualityOptionDetails>
    {
        IPrintQualityOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintQualityOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintStapleOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintStapleOptionDetails>
    {
        IPrintStapleOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintStapleOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskOptionChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskOptionChangedEventArgs>
    {
        IPrintTaskOptionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskOptionChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskOptionDetails>
    {
        IPrintTaskOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskOptionDetails2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskOptionDetails2>
    {
        IPrintTaskOptionDetails2(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskOptionDetails2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskOptionDetailsStatic :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskOptionDetailsStatic>
    {
        IPrintTaskOptionDetailsStatic(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskOptionDetailsStatic(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTextOptionDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTextOptionDetails>,
        impl::require<winrt::Windows::Graphics::Printing::OptionDetails::IPrintTextOptionDetails, winrt::Windows::Graphics::Printing::OptionDetails::IPrintOptionDetails>
    {
        IPrintTextOptionDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintTextOptionDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
