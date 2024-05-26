// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_ApplicationSettings_1_H
#define WINRT_Windows_UI_ApplicationSettings_1_H
#include "winrt/impl/Windows.UI.ApplicationSettings.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::ApplicationSettings
{
    struct __declspec(empty_bases) IAccountsSettingsPane :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAccountsSettingsPane>
    {
        IAccountsSettingsPane(std::nullptr_t = nullptr) noexcept {}
        IAccountsSettingsPane(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAccountsSettingsPaneCommandsRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAccountsSettingsPaneCommandsRequestedEventArgs>
    {
        IAccountsSettingsPaneCommandsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAccountsSettingsPaneCommandsRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAccountsSettingsPaneCommandsRequestedEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAccountsSettingsPaneCommandsRequestedEventArgs2>
    {
        IAccountsSettingsPaneCommandsRequestedEventArgs2(std::nullptr_t = nullptr) noexcept {}
        IAccountsSettingsPaneCommandsRequestedEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAccountsSettingsPaneEventDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAccountsSettingsPaneEventDeferral>
    {
        IAccountsSettingsPaneEventDeferral(std::nullptr_t = nullptr) noexcept {}
        IAccountsSettingsPaneEventDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAccountsSettingsPaneStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAccountsSettingsPaneStatics>
    {
        IAccountsSettingsPaneStatics(std::nullptr_t = nullptr) noexcept {}
        IAccountsSettingsPaneStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAccountsSettingsPaneStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAccountsSettingsPaneStatics2>,
        impl::require<winrt::Windows::UI::ApplicationSettings::IAccountsSettingsPaneStatics2, winrt::Windows::UI::ApplicationSettings::IAccountsSettingsPaneStatics>
    {
        IAccountsSettingsPaneStatics2(std::nullptr_t = nullptr) noexcept {}
        IAccountsSettingsPaneStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAccountsSettingsPaneStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAccountsSettingsPaneStatics3>
    {
        IAccountsSettingsPaneStatics3(std::nullptr_t = nullptr) noexcept {}
        IAccountsSettingsPaneStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICredentialCommand :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICredentialCommand>
    {
        ICredentialCommand(std::nullptr_t = nullptr) noexcept {}
        ICredentialCommand(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICredentialCommandFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICredentialCommandFactory>
    {
        ICredentialCommandFactory(std::nullptr_t = nullptr) noexcept {}
        ICredentialCommandFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISettingsCommandFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISettingsCommandFactory>
    {
        ISettingsCommandFactory(std::nullptr_t = nullptr) noexcept {}
        ISettingsCommandFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISettingsCommandStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISettingsCommandStatics>
    {
        ISettingsCommandStatics(std::nullptr_t = nullptr) noexcept {}
        ISettingsCommandStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISettingsPane :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISettingsPane>
    {
        ISettingsPane(std::nullptr_t = nullptr) noexcept {}
        ISettingsPane(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISettingsPaneCommandsRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISettingsPaneCommandsRequest>
    {
        ISettingsPaneCommandsRequest(std::nullptr_t = nullptr) noexcept {}
        ISettingsPaneCommandsRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISettingsPaneCommandsRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISettingsPaneCommandsRequestedEventArgs>
    {
        ISettingsPaneCommandsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISettingsPaneCommandsRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISettingsPaneStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISettingsPaneStatics>
    {
        ISettingsPaneStatics(std::nullptr_t = nullptr) noexcept {}
        ISettingsPaneStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountCommand :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountCommand>
    {
        IWebAccountCommand(std::nullptr_t = nullptr) noexcept {}
        IWebAccountCommand(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountCommandFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountCommandFactory>
    {
        IWebAccountCommandFactory(std::nullptr_t = nullptr) noexcept {}
        IWebAccountCommandFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountInvokedArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountInvokedArgs>
    {
        IWebAccountInvokedArgs(std::nullptr_t = nullptr) noexcept {}
        IWebAccountInvokedArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderCommand :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderCommand>
    {
        IWebAccountProviderCommand(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderCommand(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWebAccountProviderCommandFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWebAccountProviderCommandFactory>
    {
        IWebAccountProviderCommandFactory(std::nullptr_t = nullptr) noexcept {}
        IWebAccountProviderCommandFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
