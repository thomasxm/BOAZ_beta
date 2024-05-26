// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_AppExtensions_1_H
#define WINRT_Windows_ApplicationModel_AppExtensions_1_H
#include "winrt/impl/Windows.ApplicationModel.AppExtensions.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::AppExtensions
{
    struct __declspec(empty_bases) IAppExtension :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtension>
    {
        IAppExtension(std::nullptr_t = nullptr) noexcept {}
        IAppExtension(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtension2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtension2>
    {
        IAppExtension2(std::nullptr_t = nullptr) noexcept {}
        IAppExtension2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtensionCatalog :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtensionCatalog>
    {
        IAppExtensionCatalog(std::nullptr_t = nullptr) noexcept {}
        IAppExtensionCatalog(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtensionCatalogStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtensionCatalogStatics>
    {
        IAppExtensionCatalogStatics(std::nullptr_t = nullptr) noexcept {}
        IAppExtensionCatalogStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtensionPackageInstalledEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtensionPackageInstalledEventArgs>
    {
        IAppExtensionPackageInstalledEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppExtensionPackageInstalledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtensionPackageStatusChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtensionPackageStatusChangedEventArgs>
    {
        IAppExtensionPackageStatusChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppExtensionPackageStatusChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtensionPackageUninstallingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtensionPackageUninstallingEventArgs>
    {
        IAppExtensionPackageUninstallingEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppExtensionPackageUninstallingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtensionPackageUpdatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtensionPackageUpdatedEventArgs>
    {
        IAppExtensionPackageUpdatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppExtensionPackageUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppExtensionPackageUpdatingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppExtensionPackageUpdatingEventArgs>
    {
        IAppExtensionPackageUpdatingEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppExtensionPackageUpdatingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
