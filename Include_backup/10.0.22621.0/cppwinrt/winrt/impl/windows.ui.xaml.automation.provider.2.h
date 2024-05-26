// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Automation_Provider_2_H
#define WINRT_Windows_UI_Xaml_Automation_Provider_2_H
#include "winrt/impl/Windows.UI.Xaml.1.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Provider.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Automation::Provider
{
    struct __declspec(empty_bases) IRawElementProviderSimple : winrt::Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple,
        impl::base<IRawElementProviderSimple, winrt::Windows::UI::Xaml::DependencyObject>,
        impl::require<IRawElementProviderSimple, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>
    {
        IRawElementProviderSimple(std::nullptr_t) noexcept {}
        IRawElementProviderSimple(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple(ptr, take_ownership_from_abi) {}
    };
}
#endif
