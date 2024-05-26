// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Shell_2_H
#define WINRT_Windows_UI_Shell_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.Shell.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Shell
{
    struct AdaptiveCardBuilder
    {
        AdaptiveCardBuilder() = delete;
        static auto CreateAdaptiveCardFromJson(param::hstring const& value);
    };
    struct __declspec(empty_bases) FocusSession : winrt::Windows::UI::Shell::IFocusSession
    {
        FocusSession(std::nullptr_t) noexcept {}
        FocusSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IFocusSession(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FocusSessionManager : winrt::Windows::UI::Shell::IFocusSessionManager
    {
        FocusSessionManager(std::nullptr_t) noexcept {}
        FocusSessionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IFocusSessionManager(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
        [[nodiscard]] static auto IsSupported();
    };
    struct __declspec(empty_bases) SecurityAppManager : winrt::Windows::UI::Shell::ISecurityAppManager
    {
        SecurityAppManager(std::nullptr_t) noexcept {}
        SecurityAppManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::ISecurityAppManager(ptr, take_ownership_from_abi) {}
        SecurityAppManager();
    };
    struct __declspec(empty_bases) ShareWindowCommandEventArgs : winrt::Windows::UI::Shell::IShareWindowCommandEventArgs
    {
        ShareWindowCommandEventArgs(std::nullptr_t) noexcept {}
        ShareWindowCommandEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IShareWindowCommandEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ShareWindowCommandSource : winrt::Windows::UI::Shell::IShareWindowCommandSource
    {
        ShareWindowCommandSource(std::nullptr_t) noexcept {}
        ShareWindowCommandSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IShareWindowCommandSource(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
    struct __declspec(empty_bases) TaskbarManager : winrt::Windows::UI::Shell::ITaskbarManager,
        impl::require<TaskbarManager, winrt::Windows::UI::Shell::ITaskbarManager2>
    {
        TaskbarManager(std::nullptr_t) noexcept {}
        TaskbarManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::ITaskbarManager(ptr, take_ownership_from_abi) {}
        static auto GetDefault();
    };
    struct __declspec(empty_bases) WindowTab : winrt::Windows::UI::Shell::IWindowTab
    {
        WindowTab(std::nullptr_t) noexcept {}
        WindowTab(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTab(ptr, take_ownership_from_abi) {}
        WindowTab();
    };
    struct __declspec(empty_bases) WindowTabCloseRequestedEventArgs : winrt::Windows::UI::Shell::IWindowTabCloseRequestedEventArgs
    {
        WindowTabCloseRequestedEventArgs(std::nullptr_t) noexcept {}
        WindowTabCloseRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabCloseRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WindowTabCollection : winrt::Windows::UI::Shell::IWindowTabCollection,
        impl::require<WindowTabCollection, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Shell::WindowTab>, winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Shell::WindowTab>>
    {
        WindowTabCollection(std::nullptr_t) noexcept {}
        WindowTabCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabCollection(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WindowTabGroup : winrt::Windows::UI::Shell::IWindowTabGroup
    {
        WindowTabGroup(std::nullptr_t) noexcept {}
        WindowTabGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabGroup(ptr, take_ownership_from_abi) {}
        WindowTabGroup();
    };
    struct __declspec(empty_bases) WindowTabIcon : winrt::Windows::UI::Shell::IWindowTabIcon
    {
        WindowTabIcon(std::nullptr_t) noexcept {}
        WindowTabIcon(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabIcon(ptr, take_ownership_from_abi) {}
        static auto CreateFromFontGlyph(param::hstring const& glyph, param::hstring const& fontFamily);
        static auto CreateFromFontGlyph(param::hstring const& glyph, param::hstring const& fontFamily, winrt::Windows::Foundation::Uri const& fontUri);
        static auto CreateFromImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& image);
    };
    struct __declspec(empty_bases) WindowTabManager : winrt::Windows::UI::Shell::IWindowTabManager
    {
        WindowTabManager(std::nullptr_t) noexcept {}
        WindowTabManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabManager(ptr, take_ownership_from_abi) {}
        static auto GetForWindow(winrt::Windows::UI::WindowId const& id);
        static auto IsSupported();
        static auto IsTabTearOutSupported();
    };
    struct __declspec(empty_bases) WindowTabSwitchRequestedEventArgs : winrt::Windows::UI::Shell::IWindowTabSwitchRequestedEventArgs
    {
        WindowTabSwitchRequestedEventArgs(std::nullptr_t) noexcept {}
        WindowTabSwitchRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabSwitchRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WindowTabTearOutRequestedEventArgs : winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs
    {
        WindowTabTearOutRequestedEventArgs(std::nullptr_t) noexcept {}
        WindowTabTearOutRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabTearOutRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WindowTabThumbnailRequestedEventArgs : winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs
    {
        WindowTabThumbnailRequestedEventArgs(std::nullptr_t) noexcept {}
        WindowTabThumbnailRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Shell::IWindowTabThumbnailRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
