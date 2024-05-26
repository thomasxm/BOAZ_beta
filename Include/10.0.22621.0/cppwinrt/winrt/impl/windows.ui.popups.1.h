// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Popups_1_H
#define WINRT_Windows_UI_Popups_1_H
#include "winrt/impl/Windows.UI.Popups.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Popups
{
    struct __declspec(empty_bases) IMessageDialog :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMessageDialog>
    {
        IMessageDialog(std::nullptr_t = nullptr) noexcept {}
        IMessageDialog(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMessageDialogFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMessageDialogFactory>
    {
        IMessageDialogFactory(std::nullptr_t = nullptr) noexcept {}
        IMessageDialogFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPopupMenu :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPopupMenu>
    {
        IPopupMenu(std::nullptr_t = nullptr) noexcept {}
        IPopupMenu(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUICommand :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUICommand>
    {
        IUICommand(std::nullptr_t = nullptr) noexcept {}
        IUICommand(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUICommandFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUICommandFactory>
    {
        IUICommandFactory(std::nullptr_t = nullptr) noexcept {}
        IUICommandFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
