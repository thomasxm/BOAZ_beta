// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_UIAutomation_1_H
#define WINRT_Windows_UI_UIAutomation_1_H
#include "winrt/impl/Windows.UI.UIAutomation.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::UIAutomation
{
    struct __declspec(empty_bases) IAutomationConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAutomationConnection>
    {
        IAutomationConnection(std::nullptr_t = nullptr) noexcept {}
        IAutomationConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAutomationConnectionBoundObject :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAutomationConnectionBoundObject>
    {
        IAutomationConnectionBoundObject(std::nullptr_t = nullptr) noexcept {}
        IAutomationConnectionBoundObject(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAutomationElement :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAutomationElement>
    {
        IAutomationElement(std::nullptr_t = nullptr) noexcept {}
        IAutomationElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAutomationTextRange :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAutomationTextRange>
    {
        IAutomationTextRange(std::nullptr_t = nullptr) noexcept {}
        IAutomationTextRange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
