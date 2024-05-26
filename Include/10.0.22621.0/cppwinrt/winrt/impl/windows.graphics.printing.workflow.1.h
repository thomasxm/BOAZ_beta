// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Printing_Workflow_1_H
#define WINRT_Windows_Graphics_Printing_Workflow_1_H
#include "winrt/impl/Windows.ApplicationModel.Activation.0.h"
#include "winrt/impl/Windows.Graphics.Printing.Workflow.0.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::Workflow
{
    struct __declspec(empty_bases) IPrintWorkflowBackgroundSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowBackgroundSession>
    {
        IPrintWorkflowBackgroundSession(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowBackgroundSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowBackgroundSetupRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowBackgroundSetupRequestedEventArgs>
    {
        IPrintWorkflowBackgroundSetupRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowBackgroundSetupRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowConfiguration>
    {
        IPrintWorkflowConfiguration(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowConfiguration2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowConfiguration2>
    {
        IPrintWorkflowConfiguration2(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowConfiguration2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowForegroundSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowForegroundSession>
    {
        IPrintWorkflowForegroundSession(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowForegroundSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowForegroundSetupRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowForegroundSetupRequestedEventArgs>
    {
        IPrintWorkflowForegroundSetupRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowForegroundSetupRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowJobActivatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowJobActivatedEventArgs>
    {
        IPrintWorkflowJobActivatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowJobActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowJobBackgroundSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowJobBackgroundSession>
    {
        IPrintWorkflowJobBackgroundSession(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowJobBackgroundSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowJobNotificationEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowJobNotificationEventArgs>
    {
        IPrintWorkflowJobNotificationEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowJobNotificationEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowJobStartingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowJobStartingEventArgs>
    {
        IPrintWorkflowJobStartingEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowJobStartingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowJobTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowJobTriggerDetails>
    {
        IPrintWorkflowJobTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowJobTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowJobUISession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowJobUISession>
    {
        IPrintWorkflowJobUISession(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowJobUISession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowObjectModelSourceFileContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowObjectModelSourceFileContent>
    {
        IPrintWorkflowObjectModelSourceFileContent(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowObjectModelSourceFileContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowObjectModelSourceFileContentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowObjectModelSourceFileContentFactory>
    {
        IPrintWorkflowObjectModelSourceFileContentFactory(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowObjectModelSourceFileContentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowObjectModelTargetPackage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowObjectModelTargetPackage>
    {
        IPrintWorkflowObjectModelTargetPackage(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowObjectModelTargetPackage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPdlConverter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPdlConverter>
    {
        IPrintWorkflowPdlConverter(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPdlConverter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPdlConverter2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPdlConverter2>
    {
        IPrintWorkflowPdlConverter2(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPdlConverter2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPdlDataAvailableEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPdlDataAvailableEventArgs>
    {
        IPrintWorkflowPdlDataAvailableEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPdlDataAvailableEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPdlModificationRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPdlModificationRequestedEventArgs>
    {
        IPrintWorkflowPdlModificationRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPdlModificationRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPdlModificationRequestedEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPdlModificationRequestedEventArgs2>
    {
        IPrintWorkflowPdlModificationRequestedEventArgs2(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPdlModificationRequestedEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPdlSourceContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPdlSourceContent>
    {
        IPrintWorkflowPdlSourceContent(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPdlSourceContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPdlTargetStream :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPdlTargetStream>
    {
        IPrintWorkflowPdlTargetStream(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPdlTargetStream(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowPrinterJob :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowPrinterJob>
    {
        IPrintWorkflowPrinterJob(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowPrinterJob(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowSourceContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowSourceContent>
    {
        IPrintWorkflowSourceContent(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowSourceContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowSpoolStreamContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowSpoolStreamContent>
    {
        IPrintWorkflowSpoolStreamContent(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowSpoolStreamContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowStreamTarget :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowStreamTarget>
    {
        IPrintWorkflowStreamTarget(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowStreamTarget(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowSubmittedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowSubmittedEventArgs>
    {
        IPrintWorkflowSubmittedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowSubmittedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowSubmittedOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowSubmittedOperation>
    {
        IPrintWorkflowSubmittedOperation(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowSubmittedOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowTarget :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowTarget>
    {
        IPrintWorkflowTarget(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowTarget(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowTriggerDetails>
    {
        IPrintWorkflowTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowUIActivatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowUIActivatedEventArgs>,
        impl::require<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgs, winrt::Windows::ApplicationModel::Activation::IActivatedEventArgsWithUser>
    {
        IPrintWorkflowUIActivatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowUIActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowUILauncher :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowUILauncher>
    {
        IPrintWorkflowUILauncher(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowUILauncher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPrintWorkflowXpsDataAvailableEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPrintWorkflowXpsDataAvailableEventArgs>
    {
        IPrintWorkflowXpsDataAvailableEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPrintWorkflowXpsDataAvailableEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
