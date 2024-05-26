// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Shell_1_H
#define WINRT_Windows_UI_Shell_1_H
#include "winrt/impl/Windows.UI.Shell.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Shell
{
    struct __declspec(empty_bases) IAdaptiveCard :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAdaptiveCard>
    {
        IAdaptiveCard(std::nullptr_t = nullptr) noexcept {}
        IAdaptiveCard(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAdaptiveCardBuilderStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAdaptiveCardBuilderStatics>
    {
        IAdaptiveCardBuilderStatics(std::nullptr_t = nullptr) noexcept {}
        IAdaptiveCardBuilderStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFocusSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFocusSession>
    {
        IFocusSession(std::nullptr_t = nullptr) noexcept {}
        IFocusSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFocusSessionManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFocusSessionManager>
    {
        IFocusSessionManager(std::nullptr_t = nullptr) noexcept {}
        IFocusSessionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFocusSessionManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFocusSessionManagerStatics>
    {
        IFocusSessionManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IFocusSessionManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecurityAppManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecurityAppManager>
    {
        ISecurityAppManager(std::nullptr_t = nullptr) noexcept {}
        ISecurityAppManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IShareWindowCommandEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IShareWindowCommandEventArgs>
    {
        IShareWindowCommandEventArgs(std::nullptr_t = nullptr) noexcept {}
        IShareWindowCommandEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IShareWindowCommandSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IShareWindowCommandSource>
    {
        IShareWindowCommandSource(std::nullptr_t = nullptr) noexcept {}
        IShareWindowCommandSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IShareWindowCommandSourceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IShareWindowCommandSourceStatics>
    {
        IShareWindowCommandSourceStatics(std::nullptr_t = nullptr) noexcept {}
        IShareWindowCommandSourceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITaskbarManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITaskbarManager>
    {
        ITaskbarManager(std::nullptr_t = nullptr) noexcept {}
        ITaskbarManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITaskbarManager2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITaskbarManager2>,
        impl::require<winrt::Windows::UI::Shell::ITaskbarManager2, winrt::Windows::UI::Shell::ITaskbarManager>
    {
        ITaskbarManager2(std::nullptr_t = nullptr) noexcept {}
        ITaskbarManager2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITaskbarManagerDesktopAppSupportStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITaskbarManagerDesktopAppSupportStatics>
    {
        ITaskbarManagerDesktopAppSupportStatics(std::nullptr_t = nullptr) noexcept {}
        ITaskbarManagerDesktopAppSupportStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITaskbarManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITaskbarManagerStatics>
    {
        ITaskbarManagerStatics(std::nullptr_t = nullptr) noexcept {}
        ITaskbarManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTab :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTab>
    {
        IWindowTab(std::nullptr_t = nullptr) noexcept {}
        IWindowTab(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabCloseRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabCloseRequestedEventArgs>
    {
        IWindowTabCloseRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowTabCloseRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabCollection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabCollection>
    {
        IWindowTabCollection(std::nullptr_t = nullptr) noexcept {}
        IWindowTabCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabGroup>
    {
        IWindowTabGroup(std::nullptr_t = nullptr) noexcept {}
        IWindowTabGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabIcon :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabIcon>
    {
        IWindowTabIcon(std::nullptr_t = nullptr) noexcept {}
        IWindowTabIcon(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabIconStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabIconStatics>
    {
        IWindowTabIconStatics(std::nullptr_t = nullptr) noexcept {}
        IWindowTabIconStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabManager>
    {
        IWindowTabManager(std::nullptr_t = nullptr) noexcept {}
        IWindowTabManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabManagerStatics>
    {
        IWindowTabManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IWindowTabManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabSwitchRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabSwitchRequestedEventArgs>
    {
        IWindowTabSwitchRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowTabSwitchRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabTearOutRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabTearOutRequestedEventArgs>
    {
        IWindowTabTearOutRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowTabTearOutRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowTabThumbnailRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowTabThumbnailRequestedEventArgs>
    {
        IWindowTabThumbnailRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowTabThumbnailRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
