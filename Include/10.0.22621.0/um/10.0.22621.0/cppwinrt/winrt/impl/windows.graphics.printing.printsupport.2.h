// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Printing_PrintSupport_2_H
#define WINRT_Windows_Graphics_Printing_PrintSupport_2_H
#include "winrt/impl/Windows.ApplicationModel.Activation.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.Printing.PrintSupport.1.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::PrintSupport
{
    struct __declspec(empty_bases) PrintSupportExtensionSession : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession,
        impl::require<PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession2>
    {
        PrintSupportExtensionSession(std::nullptr_t) noexcept {}
        PrintSupportExtensionSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintSupportExtensionTriggerDetails : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionTriggerDetails
    {
        PrintSupportExtensionTriggerDetails(std::nullptr_t) noexcept {}
        PrintSupportExtensionTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintSupportPrintDeviceCapabilitiesChangedEventArgs : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs,
        impl::require<PrintSupportPrintDeviceCapabilitiesChangedEventArgs, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2>
    {
        PrintSupportPrintDeviceCapabilitiesChangedEventArgs(std::nullptr_t) noexcept {}
        PrintSupportPrintDeviceCapabilitiesChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintSupportPrintDeviceCapabilitiesUpdatePolicy : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicy
    {
        PrintSupportPrintDeviceCapabilitiesUpdatePolicy(std::nullptr_t) noexcept {}
        PrintSupportPrintDeviceCapabilitiesUpdatePolicy(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicy(ptr, take_ownership_from_abi) {}
        static auto CreatePeriodicRefresh(winrt::Windows::Foundation::TimeSpan const& updatePeriod);
        static auto CreatePrintJobRefresh(uint32_t numberOfJobs);
    };
    struct __declspec(empty_bases) PrintSupportPrintTicketElement : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement
    {
        PrintSupportPrintTicketElement(std::nullptr_t) noexcept {}
        PrintSupportPrintTicketElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement(ptr, take_ownership_from_abi) {}
        PrintSupportPrintTicketElement();
    };
    struct __declspec(empty_bases) PrintSupportPrintTicketValidationRequestedEventArgs : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs
    {
        PrintSupportPrintTicketValidationRequestedEventArgs(std::nullptr_t) noexcept {}
        PrintSupportPrintTicketValidationRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintSupportPrinterSelectedEventArgs : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs
    {
        PrintSupportPrinterSelectedEventArgs(std::nullptr_t) noexcept {}
        PrintSupportPrinterSelectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintSupportSessionInfo : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSessionInfo
    {
        PrintSupportSessionInfo(std::nullptr_t) noexcept {}
        PrintSupportSessionInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSessionInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintSupportSettingsActivatedEventArgs : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsActivatedEventArgs,
        impl::require<PrintSupportSettingsActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        PrintSupportSettingsActivatedEventArgs(std::nullptr_t) noexcept {}
        PrintSupportSettingsActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsActivatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintSupportSettingsUISession : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession
    {
        PrintSupportSettingsUISession(std::nullptr_t) noexcept {}
        PrintSupportSettingsUISession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession(ptr, take_ownership_from_abi) {}
    };
}
#endif
