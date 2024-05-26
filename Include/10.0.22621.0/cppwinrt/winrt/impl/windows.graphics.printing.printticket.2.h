// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Printing_PrintTicket_2_H
#define WINRT_Windows_Graphics_Printing_PrintTicket_2_H
#include "winrt/impl/Windows.Graphics.Printing.PrintTicket.1.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::PrintTicket
{
    struct __declspec(empty_bases) PrintTicketCapabilities : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities
    {
        PrintTicketCapabilities(std::nullptr_t) noexcept {}
        PrintTicketCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTicketFeature : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature
    {
        PrintTicketFeature(std::nullptr_t) noexcept {}
        PrintTicketFeature(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTicketOption : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption
    {
        PrintTicketOption(std::nullptr_t) noexcept {}
        PrintTicketOption(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTicketParameterDefinition : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition
    {
        PrintTicketParameterDefinition(std::nullptr_t) noexcept {}
        PrintTicketParameterDefinition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTicketParameterInitializer : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer
    {
        PrintTicketParameterInitializer(std::nullptr_t) noexcept {}
        PrintTicketParameterInitializer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PrintTicketValue : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue
    {
        PrintTicketValue(std::nullptr_t) noexcept {}
        PrintTicketValue(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WorkflowPrintTicket : winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket
    {
        WorkflowPrintTicket(std::nullptr_t) noexcept {}
        WorkflowPrintTicket(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WorkflowPrintTicketValidationResult : winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult
    {
        WorkflowPrintTicketValidationResult(std::nullptr_t) noexcept {}
        WorkflowPrintTicketValidationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult(ptr, take_ownership_from_abi) {}
    };
}
#endif
