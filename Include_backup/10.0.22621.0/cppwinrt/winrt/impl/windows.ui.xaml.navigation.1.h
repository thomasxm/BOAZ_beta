// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Navigation_1_H
#define WINRT_Windows_UI_Xaml_Navigation_1_H
#include "winrt/impl/Windows.UI.Xaml.Navigation.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Navigation
{
    struct __declspec(empty_bases) IFrameNavigationOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFrameNavigationOptions>
    {
        IFrameNavigationOptions(std::nullptr_t = nullptr) noexcept {}
        IFrameNavigationOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFrameNavigationOptionsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFrameNavigationOptionsFactory>
    {
        IFrameNavigationOptionsFactory(std::nullptr_t = nullptr) noexcept {}
        IFrameNavigationOptionsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INavigatingCancelEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INavigatingCancelEventArgs>
    {
        INavigatingCancelEventArgs(std::nullptr_t = nullptr) noexcept {}
        INavigatingCancelEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INavigatingCancelEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INavigatingCancelEventArgs2>
    {
        INavigatingCancelEventArgs2(std::nullptr_t = nullptr) noexcept {}
        INavigatingCancelEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INavigationEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INavigationEventArgs>
    {
        INavigationEventArgs(std::nullptr_t = nullptr) noexcept {}
        INavigationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INavigationEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INavigationEventArgs2>
    {
        INavigationEventArgs2(std::nullptr_t = nullptr) noexcept {}
        INavigationEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INavigationFailedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INavigationFailedEventArgs>
    {
        INavigationFailedEventArgs(std::nullptr_t = nullptr) noexcept {}
        INavigationFailedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPageStackEntry :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPageStackEntry>
    {
        IPageStackEntry(std::nullptr_t = nullptr) noexcept {}
        IPageStackEntry(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPageStackEntryFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPageStackEntryFactory>
    {
        IPageStackEntryFactory(std::nullptr_t = nullptr) noexcept {}
        IPageStackEntryFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPageStackEntryStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPageStackEntryStatics>
    {
        IPageStackEntryStatics(std::nullptr_t = nullptr) noexcept {}
        IPageStackEntryStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
