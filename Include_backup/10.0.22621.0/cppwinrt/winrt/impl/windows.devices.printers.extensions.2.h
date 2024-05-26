// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Printers_Extensions_2_H
#define WINRT_Windows_Devices_Printers_Extensions_2_H
#include "winrt/impl/Windows.Devices.Printers.Extensions.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Printers::Extensions
{
    struct __declspec(empty_bases) Print3DWorkflow : winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow,
        impl::require<Print3DWorkflow, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2>
    {
        Print3DWorkflow(std::nullptr_t) noexcept {}
        Print3DWorkflow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) Print3DWorkflowPrintRequestedEventArgs : winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs
    {
        Print3DWorkflowPrintRequestedEventArgs(std::nullptr_t) noexcept {}
        Print3DWorkflowPrintRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) Print3DWorkflowPrinterChangedEventArgs : winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs
    {
        Print3DWorkflowPrinterChangedEventArgs(std::nullptr_t) noexcept {}
        Print3DWorkflowPrinterChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct PrintExtensionContext
    {
        PrintExtensionContext() = delete;
        static auto FromDeviceId(param::hstring const& deviceId);
    };
    struct __declspec(empty_bases) PrintNotificationEventDetails : winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails
    {
        PrintNotificationEventDetails(std::nullptr_t) noexcept {}
        PrintNotificationEventDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTaskConfiguration : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration
    {
        PrintTaskConfiguration(std::nullptr_t) noexcept {}
        PrintTaskConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTaskConfigurationSaveRequest : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest
    {
        PrintTaskConfigurationSaveRequest(std::nullptr_t) noexcept {}
        PrintTaskConfigurationSaveRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTaskConfigurationSaveRequestedDeferral : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral
    {
        PrintTaskConfigurationSaveRequestedDeferral(std::nullptr_t) noexcept {}
        PrintTaskConfigurationSaveRequestedDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTaskConfigurationSaveRequestedEventArgs : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs
    {
        PrintTaskConfigurationSaveRequestedEventArgs(std::nullptr_t) noexcept {}
        PrintTaskConfigurationSaveRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
