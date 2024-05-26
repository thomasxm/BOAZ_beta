// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Contacts_Provider_1_H
#define WINRT_Windows_ApplicationModel_Contacts_Provider_1_H
#include "winrt/impl/Windows.ApplicationModel.Contacts.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::Provider
{
    struct __declspec(empty_bases) IContactPickerUI :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPickerUI>
    {
        IContactPickerUI(std::nullptr_t = nullptr) noexcept {}
        IContactPickerUI(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactPickerUI2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactPickerUI2>
    {
        IContactPickerUI2(std::nullptr_t = nullptr) noexcept {}
        IContactPickerUI2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IContactRemovedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IContactRemovedEventArgs>
    {
        IContactRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IContactRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
