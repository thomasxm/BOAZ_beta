// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_UIAutomation_2_H
#define WINRT_Windows_UI_UIAutomation_2_H
#include "winrt/impl/Windows.UI.UIAutomation.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::UIAutomation
{
    struct __declspec(empty_bases) AutomationConnection : winrt::Windows::UI::UIAutomation::IAutomationConnection
    {
        AutomationConnection(std::nullptr_t) noexcept {}
        AutomationConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::IAutomationConnection(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AutomationConnectionBoundObject : winrt::Windows::UI::UIAutomation::IAutomationConnectionBoundObject
    {
        AutomationConnectionBoundObject(std::nullptr_t) noexcept {}
        AutomationConnectionBoundObject(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::IAutomationConnectionBoundObject(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AutomationElement : winrt::Windows::UI::UIAutomation::IAutomationElement
    {
        AutomationElement(std::nullptr_t) noexcept {}
        AutomationElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::IAutomationElement(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AutomationTextRange : winrt::Windows::UI::UIAutomation::IAutomationTextRange
    {
        AutomationTextRange(std::nullptr_t) noexcept {}
        AutomationTextRange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::UIAutomation::IAutomationTextRange(ptr, take_ownership_from_abi) {}
    };
}
#endif
