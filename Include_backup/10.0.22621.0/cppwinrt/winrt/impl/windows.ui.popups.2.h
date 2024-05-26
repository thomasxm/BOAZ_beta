// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Popups_2_H
#define WINRT_Windows_UI_Popups_2_H
#include "winrt/impl/Windows.UI.Popups.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Popups
{
    struct UICommandInvokedHandler : winrt::Windows::Foundation::IUnknown
    {
        UICommandInvokedHandler(std::nullptr_t = nullptr) noexcept {}
        UICommandInvokedHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> UICommandInvokedHandler(L lambda);
        template <typename F> UICommandInvokedHandler(F* function);
        template <typename O, typename M> UICommandInvokedHandler(O* object, M method);
        template <typename O, typename M> UICommandInvokedHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> UICommandInvokedHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::UI::Popups::IUICommand const& command) const;
    };
    struct __declspec(empty_bases) MessageDialog : winrt::Windows::UI::Popups::IMessageDialog
    {
        MessageDialog(std::nullptr_t) noexcept {}
        MessageDialog(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Popups::IMessageDialog(ptr, take_ownership_from_abi) {}
        explicit MessageDialog(param::hstring const& content);
        MessageDialog(param::hstring const& content, param::hstring const& title);
    };
    struct __declspec(empty_bases) PopupMenu : winrt::Windows::UI::Popups::IPopupMenu
    {
        PopupMenu(std::nullptr_t) noexcept {}
        PopupMenu(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Popups::IPopupMenu(ptr, take_ownership_from_abi) {}
        PopupMenu();
    };
    struct __declspec(empty_bases) UICommand : winrt::Windows::UI::Popups::IUICommand
    {
        UICommand(std::nullptr_t) noexcept {}
        UICommand(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Popups::IUICommand(ptr, take_ownership_from_abi) {}
        UICommand();
        explicit UICommand(param::hstring const& label);
        UICommand(param::hstring const& label, winrt::Windows::UI::Popups::UICommandInvokedHandler const& action);
        UICommand(param::hstring const& label, winrt::Windows::UI::Popups::UICommandInvokedHandler const& action, winrt::Windows::Foundation::IInspectable const& commandId);
    };
    struct __declspec(empty_bases) UICommandSeparator : winrt::Windows::UI::Popups::IUICommand
    {
        UICommandSeparator(std::nullptr_t) noexcept {}
        UICommandSeparator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Popups::IUICommand(ptr, take_ownership_from_abi) {}
        UICommandSeparator();
    };
}
#endif
