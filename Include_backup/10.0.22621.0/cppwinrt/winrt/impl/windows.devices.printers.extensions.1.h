// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Printers_Extensions_1_H
#define WINRT_Windows_Devices_Printers_Extensions_1_H
#include "winrt/impl/Windows.Devices.Printers.Extensions.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Printers::Extensions
{
    struct __declspec(empty_bases) IPrint3DWorkflow :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrint3DWorkflow>
    {
        IPrint3DWorkflow(std::nullptr_t = nullptr) noexcept {}
        IPrint3DWorkflow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrint3DWorkflow2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrint3DWorkflow2>
    {
        IPrint3DWorkflow2(std::nullptr_t = nullptr) noexcept {}
        IPrint3DWorkflow2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrint3DWorkflowPrintRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrint3DWorkflowPrintRequestedEventArgs>
    {
        IPrint3DWorkflowPrintRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrint3DWorkflowPrintRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrint3DWorkflowPrinterChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrint3DWorkflowPrinterChangedEventArgs>
    {
        IPrint3DWorkflowPrinterChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrint3DWorkflowPrinterChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintExtensionContextStatic :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintExtensionContextStatic>
    {
        IPrintExtensionContextStatic(std::nullptr_t = nullptr) noexcept {}
        IPrintExtensionContextStatic(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintNotificationEventDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintNotificationEventDetails>
    {
        IPrintNotificationEventDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintNotificationEventDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskConfiguration>
    {
        IPrintTaskConfiguration(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskConfigurationSaveRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskConfigurationSaveRequest>
    {
        IPrintTaskConfigurationSaveRequest(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskConfigurationSaveRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskConfigurationSaveRequestedDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskConfigurationSaveRequestedDeferral>
    {
        IPrintTaskConfigurationSaveRequestedDeferral(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskConfigurationSaveRequestedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintTaskConfigurationSaveRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintTaskConfigurationSaveRequestedEventArgs>
    {
        IPrintTaskConfigurationSaveRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintTaskConfigurationSaveRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
