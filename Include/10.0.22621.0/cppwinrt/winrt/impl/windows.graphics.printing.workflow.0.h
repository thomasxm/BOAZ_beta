// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Printing_Workflow_0_H
#define WINRT_Windows_Graphics_Printing_Workflow_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Printers
{
    struct IppAttributeValue;
    struct IppPrintDevice;
    struct IppSetAttributesResult;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct Deferral;
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IKeyValuePair;
    template <typename K, typename V> struct __declspec(empty_bases) IMap;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::PrintTicket
{
    struct WorkflowPrintTicket;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct StorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
    struct IInputStream;
    struct IOutputStream;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::Workflow
{
    enum class PdlConversionHostBasedProcessingOperations : uint32_t
    {
        None = 0,
        PageRotation = 0x1,
        PageOrdering = 0x2,
        Copies = 0x4,
        BlankPageInsertion = 0x8,
        All = 0xffffffff,
    };
    enum class PrintWorkflowAttributesMergePolicy : int32_t
    {
        MergePreferPrintTicketOnConflict = 0,
        MergePreferPsaOnConflict = 1,
        DoNotMergeWithPrintTicket = 2,
    };
    enum class PrintWorkflowJobAbortReason : int32_t
    {
        JobFailed = 0,
        UserCanceled = 1,
    };
    enum class PrintWorkflowPdlConversionType : int32_t
    {
        XpsToPdf = 0,
        XpsToPwgr = 1,
        XpsToPclm = 2,
    };
    enum class PrintWorkflowPrinterJobStatus : int32_t
    {
        Error = 0,
        Aborted = 1,
        InProgress = 2,
        Completed = 3,
    };
    enum class PrintWorkflowSessionStatus : int32_t
    {
        Started = 0,
        Completed = 1,
        Aborted = 2,
        Closed = 3,
        PdlDataAvailableForModification = 4,
    };
    enum class PrintWorkflowSubmittedStatus : int32_t
    {
        Succeeded = 0,
        Canceled = 1,
        Failed = 2,
    };
    enum class PrintWorkflowUICompletionStatus : int32_t
    {
        Completed = 0,
        LaunchFailed = 1,
        JobFailed = 2,
        UserCanceled = 3,
    };
    struct IPrintWorkflowBackgroundSession;
    struct IPrintWorkflowBackgroundSetupRequestedEventArgs;
    struct IPrintWorkflowConfiguration;
    struct IPrintWorkflowConfiguration2;
    struct IPrintWorkflowForegroundSession;
    struct IPrintWorkflowForegroundSetupRequestedEventArgs;
    struct IPrintWorkflowJobActivatedEventArgs;
    struct IPrintWorkflowJobBackgroundSession;
    struct IPrintWorkflowJobNotificationEventArgs;
    struct IPrintWorkflowJobStartingEventArgs;
    struct IPrintWorkflowJobTriggerDetails;
    struct IPrintWorkflowJobUISession;
    struct IPrintWorkflowObjectModelSourceFileContent;
    struct IPrintWorkflowObjectModelSourceFileContentFactory;
    struct IPrintWorkflowObjectModelTargetPackage;
    struct IPrintWorkflowPdlConverter;
    struct IPrintWorkflowPdlConverter2;
    struct IPrintWorkflowPdlDataAvailableEventArgs;
    struct IPrintWorkflowPdlModificationRequestedEventArgs;
    struct IPrintWorkflowPdlModificationRequestedEventArgs2;
    struct IPrintWorkflowPdlSourceContent;
    struct IPrintWorkflowPdlTargetStream;
    struct IPrintWorkflowPrinterJob;
    struct IPrintWorkflowSourceContent;
    struct IPrintWorkflowSpoolStreamContent;
    struct IPrintWorkflowStreamTarget;
    struct IPrintWorkflowSubmittedEventArgs;
    struct IPrintWorkflowSubmittedOperation;
    struct IPrintWorkflowTarget;
    struct IPrintWorkflowTriggerDetails;
    struct IPrintWorkflowUIActivatedEventArgs;
    struct IPrintWorkflowUILauncher;
    struct IPrintWorkflowXpsDataAvailableEventArgs;
    struct PrintWorkflowBackgroundSession;
    struct PrintWorkflowBackgroundSetupRequestedEventArgs;
    struct PrintWorkflowConfiguration;
    struct PrintWorkflowForegroundSession;
    struct PrintWorkflowForegroundSetupRequestedEventArgs;
    struct PrintWorkflowJobActivatedEventArgs;
    struct PrintWorkflowJobBackgroundSession;
    struct PrintWorkflowJobNotificationEventArgs;
    struct PrintWorkflowJobStartingEventArgs;
    struct PrintWorkflowJobTriggerDetails;
    struct PrintWorkflowJobUISession;
    struct PrintWorkflowObjectModelSourceFileContent;
    struct PrintWorkflowObjectModelTargetPackage;
    struct PrintWorkflowPdlConverter;
    struct PrintWorkflowPdlDataAvailableEventArgs;
    struct PrintWorkflowPdlModificationRequestedEventArgs;
    struct PrintWorkflowPdlSourceContent;
    struct PrintWorkflowPdlTargetStream;
    struct PrintWorkflowPrinterJob;
    struct PrintWorkflowSourceContent;
    struct PrintWorkflowSpoolStreamContent;
    struct PrintWorkflowStreamTarget;
    struct PrintWorkflowSubmittedEventArgs;
    struct PrintWorkflowSubmittedOperation;
    struct PrintWorkflowTarget;
    struct PrintWorkflowTriggerDetails;
    struct PrintWorkflowUIActivatedEventArgs;
    struct PrintWorkflowUILauncher;
    struct PrintWorkflowXpsDataAvailableEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobActivatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobNotificationEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobStartingEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContentFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlDataAvailableEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlSourceContent>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlTargetStream>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPrinterJob>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUILauncher>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobActivatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobNotificationEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobStartingEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlConverter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlDataAvailableEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlModificationRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlSourceContent>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJob>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTarget>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUILauncher>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PdlConversionHostBasedProcessingOperations>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowAttributesMergePolicy>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobAbortReason>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlConversionType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJobStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUICompletionStatus>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowBackgroundSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowBackgroundSetupRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowConfiguration";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowForegroundSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowForegroundSetupRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobActivatedEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowJobActivatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowJobBackgroundSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobNotificationEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowJobNotificationEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobStartingEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowJobStartingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobTriggerDetails> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowJobTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowJobUISession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowObjectModelSourceFileContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowObjectModelTargetPackage";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlConverter> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPdlConverter";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlDataAvailableEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPdlDataAvailableEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlModificationRequestedEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPdlModificationRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlSourceContent> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPdlSourceContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPdlTargetStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJob> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPrinterJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowSourceContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowSpoolStreamContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowStreamTarget";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowSubmittedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowSubmittedOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTarget> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowTarget";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowUIActivatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUILauncher> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowUILauncher";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowXpsDataAvailableEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PdlConversionHostBasedProcessingOperations> = L"Windows.Graphics.Printing.Workflow.PdlConversionHostBasedProcessingOperations";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowAttributesMergePolicy> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowAttributesMergePolicy";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobAbortReason> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowJobAbortReason";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlConversionType> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPdlConversionType";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJobStatus> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowPrinterJobStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowSessionStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowSubmittedStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUICompletionStatus> = L"Windows.Graphics.Printing.Workflow.PrintWorkflowUICompletionStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowBackgroundSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowBackgroundSetupRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowConfiguration";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration2> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowConfiguration2";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowForegroundSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowForegroundSetupRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobActivatedEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowJobActivatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowJobBackgroundSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobNotificationEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowJobNotificationEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobStartingEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowJobStartingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobTriggerDetails> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowJobTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowJobUISession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowObjectModelSourceFileContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContentFactory> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowObjectModelSourceFileContentFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowObjectModelTargetPackage";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPdlConverter";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter2> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPdlConverter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlDataAvailableEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPdlDataAvailableEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPdlModificationRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs2> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPdlModificationRequestedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlSourceContent> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPdlSourceContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlTargetStream> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPdlTargetStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPrinterJob> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowPrinterJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSourceContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSpoolStreamContent";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowStreamTarget";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSubmittedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowSubmittedOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowTarget";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowUIActivatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUILauncher> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowUILauncher";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs> = L"Windows.Graphics.Printing.Workflow.IPrintWorkflowXpsDataAvailableEventArgs";
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>{ 0x5B7913BA,0x0C5E,0x528A,{ 0x74,0x58,0x86,0xA4,0x6C,0xBD,0xDC,0x45 } }; // 5B7913BA-0C5E-528A-7458-86A46CBDDC45
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>{ 0x43E97342,0x1750,0x59C9,{ 0x61,0xFB,0x38,0x37,0x48,0xA2,0x03,0x62 } }; // 43E97342-1750-59C9-61FB-383748A20362
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>{ 0xD0AAC4ED,0xFD4B,0x5DF5,{ 0x4B,0xB6,0x8D,0x0D,0x15,0x9E,0xBE,0x3F } }; // D0AAC4ED-FD4B-5DF5-4BB6-8D0D159EBE3F
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration2>{ 0xDE350A50,0xA6D4,0x5BE2,{ 0x8B,0x9A,0x09,0xD3,0xD3,0x9E,0xA7,0x80 } }; // DE350A50-A6D4-5BE2-8B9A-09D3D39EA780
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>{ 0xC79B63D0,0xF8EC,0x4CEB,{ 0x95,0x3A,0xC8,0x87,0x61,0x57,0xDD,0x33 } }; // C79B63D0-F8EC-4CEB-953A-C8876157DD33
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>{ 0xBBE38247,0x9C1B,0x4DD3,{ 0x9B,0x2B,0xC8,0x04,0x68,0xD9,0x41,0xB3 } }; // BBE38247-9C1B-4DD3-9B2B-C80468D941B3
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobActivatedEventArgs>{ 0xD4BD5E6D,0x034E,0x5E00,{ 0xA6,0x16,0xF9,0x61,0xA0,0x33,0xDC,0xC8 } }; // D4BD5E6D-034E-5E00-A616-F961A033DCC8
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession>{ 0xC5EC6AD8,0x20C9,0x5D51,{ 0x85,0x07,0x27,0x34,0xB4,0x6F,0x96,0xC5 } }; // C5EC6AD8-20C9-5D51-8507-2734B46F96C5
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobNotificationEventArgs>{ 0x0AE16FBA,0x5398,0x5EBA,{ 0xB4,0x72,0x97,0x86,0x50,0x18,0x6A,0x9A } }; // 0AE16FBA-5398-5EBA-B472-978650186A9A
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobStartingEventArgs>{ 0xE3D99BA8,0x31AD,0x5E09,{ 0xB0,0xD7,0x60,0x1B,0x97,0xF1,0x61,0xAD } }; // E3D99BA8-31AD-5E09-B0D7-601B97F161AD
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobTriggerDetails>{ 0xFF296129,0x60E2,0x51DB,{ 0xBA,0x8C,0xE2,0xCC,0xDD,0xB5,0x16,0xB9 } }; // FF296129-60E2-51DB-BA8C-E2CCDDB516B9
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession>{ 0x00C8736B,0x7637,0x5687,{ 0xA3,0x02,0x0F,0x66,0x4D,0x2A,0xAC,0x65 } }; // 00C8736B-7637-5687-A302-0F664D2AAC65
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>{ 0xC36C8A6A,0x8A2A,0x419A,{ 0xB3,0xC3,0x20,0x90,0xE6,0xBF,0xAB,0x2F } }; // C36C8A6A-8A2A-419A-B3C3-2090E6BFAB2F
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContentFactory>{ 0x93B1B903,0xF013,0x56D6,{ 0xB7,0x08,0x99,0xAC,0x2C,0xCB,0x12,0xEE } }; // 93B1B903-F013-56D6-B708-99AC2CCB12EE
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>{ 0x7D96BC74,0x9B54,0x4CA1,{ 0xAD,0x3A,0x97,0x9C,0x3D,0x44,0xDD,0xAC } }; // 7D96BC74-9B54-4CA1-AD3A-979C3D44DDAC
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter>{ 0x40604B62,0x0AE4,0x51F1,{ 0x81,0x8F,0x73,0x1D,0xC0,0xB0,0x05,0xAB } }; // 40604B62-0AE4-51F1-818F-731DC0B005AB
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter2>{ 0x854CEEC1,0x7837,0x5B93,{ 0xB7,0xAF,0x57,0xA6,0x99,0x8C,0x2F,0x71 } }; // 854CEEC1-7837-5B93-B7AF-57A6998C2F71
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlDataAvailableEventArgs>{ 0xD4AD6B50,0x1547,0x5991,{ 0xA0,0xEF,0xE2,0xEE,0x20,0x21,0x15,0x18 } }; // D4AD6B50-1547-5991-A0EF-E2EE20211518
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs>{ 0x1A339A61,0x2E13,0x5EDD,{ 0xA7,0x07,0xCE,0xEC,0x61,0xD7,0x33,0x3B } }; // 1A339A61-2E13-5EDD-A707-CEEC61D7333B
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs2>{ 0x8D692147,0x6C62,0x5E31,{ 0xA0,0xE7,0xD4,0x9F,0x92,0xC1,0x11,0xC0 } }; // 8D692147-6C62-5E31-A0E7-D49F92C111C0
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlSourceContent>{ 0x92F7FC41,0x32B8,0x56AB,{ 0x84,0x5E,0xB1,0xE6,0x8B,0x3A,0xED,0xD5 } }; // 92F7FC41-32B8-56AB-845E-B1E68B3AEDD5
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlTargetStream>{ 0xA742DFE5,0x1EE3,0x52A9,{ 0x9F,0x9F,0x2E,0x20,0x43,0x18,0x0F,0xD1 } }; // A742DFE5-1EE3-52A9-9F9F-2E2043180FD1
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPrinterJob>{ 0x12009F94,0x0D14,0x5443,{ 0xBC,0x09,0x25,0x03,0x11,0xCE,0x57,0x0B } }; // 12009F94-0D14-5443-BC09-250311CE570B
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>{ 0x1A28C641,0xCEB1,0x4533,{ 0xBB,0x73,0xFB,0xE6,0x3E,0xEF,0xDB,0x18 } }; // 1A28C641-CEB1-4533-BB73-FBE63EEFDB18
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>{ 0x72E55ECE,0xE406,0x4B74,{ 0x84,0xE1,0x3F,0xF3,0xFD,0xCD,0xAF,0x70 } }; // 72E55ECE-E406-4B74-84E1-3FF3FDCDAF70
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>{ 0xB23BBA84,0x8565,0x488B,{ 0x98,0x39,0x1C,0x9E,0x7C,0x7A,0xA9,0x16 } }; // B23BBA84-8565-488B-9839-1C9E7C7AA916
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>{ 0x3ADD0A41,0x3794,0x5569,{ 0x5C,0x87,0x40,0xE8,0xFF,0x72,0x0F,0x83 } }; // 3ADD0A41-3794-5569-5C87-40E8FF720F83
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>{ 0x2E4E6216,0x3BE1,0x5F0F,{ 0x5C,0x81,0xA5,0xA2,0xBD,0x4E,0xAB,0x0E } }; // 2E4E6216-3BE1-5F0F-5C81-A5A2BD4EAB0E
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>{ 0x29DA276C,0x0A73,0x5AED,{ 0x4F,0x3D,0x97,0x0D,0x32,0x51,0xF0,0x57 } }; // 29DA276C-0A73-5AED-4F3D-970D3251F057
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>{ 0x5739D868,0x9D86,0x4052,{ 0xB0,0xCB,0xF3,0x10,0xBE,0xCD,0x59,0xBB } }; // 5739D868-9D86-4052-B0CB-F310BECD59BB
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>{ 0xBC8A844D,0x09EB,0x5746,{ 0x72,0xA6,0x8D,0xC8,0xB5,0xED,0xBE,0x9B } }; // BC8A844D-09EB-5746-72A6-8DC8B5EDBE9B
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUILauncher>{ 0x64E9E22F,0x14CC,0x5828,{ 0x96,0xFB,0x39,0x16,0x3F,0xB6,0xC3,0x78 } }; // 64E9E22F-14CC-5828-96FB-39163FB6C378
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>{ 0x4D11C331,0x54D1,0x434E,{ 0xBE,0x0E,0x82,0xC5,0xFA,0x58,0xE5,0xB2 } }; // 4D11C331-54D1-434E-BE0E-82C5FA58E5B2
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobActivatedEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobActivatedEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobNotificationEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobNotificationEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobStartingEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobStartingEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobTriggerDetails>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlConverter>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlDataAvailableEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlDataAvailableEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlModificationRequestedEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlSourceContent>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlSourceContent; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlTargetStream; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJob>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPrinterJob; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTarget>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUILauncher>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUILauncher; };
    template <> struct default_interface<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs>{ using type = winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs; };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_SetupRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SetupRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Submitted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Submitted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetUserPrintTicketAsync(void**) noexcept = 0;
            virtual int32_t __stdcall get_Configuration(void**) noexcept = 0;
            virtual int32_t __stdcall SetRequiresUI() noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SourceAppDisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall get_JobTitle(void**) noexcept = 0;
            virtual int32_t __stdcall get_SessionId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AbortPrintFlow(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_SetupRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SetupRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_XpsDataAvailable(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_XpsDataAvailable(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetUserPrintTicketAsync(void**) noexcept = 0;
            virtual int32_t __stdcall get_Configuration(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobActivatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Session(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_JobStarting(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_JobStarting(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PdlModificationRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PdlModificationRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobNotificationEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Configuration(void**) noexcept = 0;
            virtual int32_t __stdcall get_PrinterJob(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobStartingEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Configuration(void**) noexcept = 0;
            virtual int32_t __stdcall get_Printer(void**) noexcept = 0;
            virtual int32_t __stdcall SetSkipSystemRendering() noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PrintWorkflowJobSession(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_PdlDataAvailable(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PdlDataAvailable(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_JobNotification(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_JobNotification(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall Start() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContentFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ConvertPdlAsync(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ConvertPdlAsync(void*, void*, void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlDataAvailableEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Configuration(void**) noexcept = 0;
            virtual int32_t __stdcall get_PrinterJob(void**) noexcept = 0;
            virtual int32_t __stdcall get_SourceContent(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Configuration(void**) noexcept = 0;
            virtual int32_t __stdcall get_PrinterJob(void**) noexcept = 0;
            virtual int32_t __stdcall get_SourceContent(void**) noexcept = 0;
            virtual int32_t __stdcall get_UILauncher(void**) noexcept = 0;
            virtual int32_t __stdcall CreateJobOnPrinter(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateJobOnPrinterWithAttributes(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateJobOnPrinterWithAttributesBuffer(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetPdlConverter(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateJobOnPrinterWithAttributes(void*, void*, void*, int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateJobOnPrinterWithAttributesBuffer(void*, void*, void*, int32_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlSourceContent>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContentType(void**) noexcept = 0;
            virtual int32_t __stdcall GetInputStream(void**) noexcept = 0;
            virtual int32_t __stdcall GetContentFileAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlTargetStream>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetOutputStream(void**) noexcept = 0;
            virtual int32_t __stdcall CompleteStreamSubmission(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPrinterJob>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_JobId(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Printer(void**) noexcept = 0;
            virtual int32_t __stdcall GetJobStatus(int32_t*) noexcept = 0;
            virtual int32_t __stdcall GetJobPrintTicket(void**) noexcept = 0;
            virtual int32_t __stdcall GetJobAttributesAsBuffer(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetJobAttributes(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetJobAttributesFromBuffer(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetJobAttributes(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetJobPrintTicketAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetSourceSpoolDataAsStreamContent(void**) noexcept = 0;
            virtual int32_t __stdcall GetSourceSpoolDataAsXpsObjectModel(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetInputStream(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetOutputStream(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Operation(void**) noexcept = 0;
            virtual int32_t __stdcall GetTarget(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Complete(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_Configuration(void**) noexcept = 0;
            virtual int32_t __stdcall get_XpsContent(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TargetAsStream(void**) noexcept = 0;
            virtual int32_t __stdcall get_TargetAsXpsObjectModelPackage(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PrintWorkflowSession(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PrintWorkflowSession(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUILauncher>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsUILaunchEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall LaunchAndCompleteUIAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Operation(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession
    {
        WINRT_IMPL_AUTO(winrt::event_token) SetupRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const& setupEventHandler) const;
        using SetupRequested_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>::remove_SetupRequested>;
        [[nodiscard]] SetupRequested_revoker SetupRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const& setupEventHandler) const;
        WINRT_IMPL_AUTO(void) SetupRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Submitted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const& submittedEventHandler) const;
        using Submitted_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>::remove_Submitted>;
        [[nodiscard]] Submitted_revoker Submitted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const& submittedEventHandler) const;
        WINRT_IMPL_AUTO(void) Submitted(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus) Status() const;
        WINRT_IMPL_AUTO(void) Start() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>) GetUserPrintTicketAsync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration) Configuration() const;
        WINRT_IMPL_AUTO(void) SetRequiresUI() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SourceAppDisplayName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) JobTitle() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SessionId() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration2
    {
        WINRT_IMPL_AUTO(void) AbortPrintFlow(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobAbortReason const& reason) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration2>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration2<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession
    {
        WINRT_IMPL_AUTO(winrt::event_token) SetupRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const& setupEventHandler) const;
        using SetupRequested_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>::remove_SetupRequested>;
        [[nodiscard]] SetupRequested_revoker SetupRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const& setupEventHandler) const;
        WINRT_IMPL_AUTO(void) SetupRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) XpsDataAvailable(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const& xpsDataAvailableEventHandler) const;
        using XpsDataAvailable_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>::remove_XpsDataAvailable>;
        [[nodiscard]] XpsDataAvailable_revoker XpsDataAvailable(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const& xpsDataAvailableEventHandler) const;
        WINRT_IMPL_AUTO(void) XpsDataAvailable(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus) Status() const;
        WINRT_IMPL_AUTO(void) Start() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSetupRequestedEventArgs
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>) GetUserPrintTicketAsync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration) Configuration() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSetupRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobActivatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession) Session() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobActivatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobActivatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobBackgroundSession
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus) Status() const;
        WINRT_IMPL_AUTO(winrt::event_token) JobStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobStartingEventArgs> const& handler) const;
        using JobStarting_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession>::remove_JobStarting>;
        [[nodiscard]] JobStarting_revoker JobStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobStartingEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) JobStarting(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PdlModificationRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlModificationRequestedEventArgs> const& handler) const;
        using PdlModificationRequested_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession>::remove_PdlModificationRequested>;
        [[nodiscard]] PdlModificationRequested_revoker PdlModificationRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlModificationRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PdlModificationRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) Start() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobBackgroundSession>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobBackgroundSession<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobNotificationEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration) Configuration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJob) PrinterJob() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobNotificationEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobNotificationEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobStartingEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration) Configuration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppPrintDevice) Printer() const;
        WINRT_IMPL_AUTO(void) SetSkipSystemRendering() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobStartingEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobStartingEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobBackgroundSession) PrintWorkflowJobSession() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobUISession
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus) Status() const;
        WINRT_IMPL_AUTO(winrt::event_token) PdlDataAvailable(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlDataAvailableEventArgs> const& handler) const;
        using PdlDataAvailable_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession>::remove_PdlDataAvailable>;
        [[nodiscard]] PdlDataAvailable_revoker PdlDataAvailable(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlDataAvailableEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) PdlDataAvailable(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) JobNotification(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobNotificationEventArgs> const& handler) const;
        using JobNotification_revoker = impl::event_revoker<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession, &impl::abi_t<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession>::remove_JobNotification>;
        [[nodiscard]] JobNotification_revoker JobNotification(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobUISession, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowJobNotificationEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) JobNotification(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) Start() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowJobUISession>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowJobUISession<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelSourceFileContent
    {
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelSourceFileContent<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelSourceFileContentFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent) CreateInstance(winrt::Windows::Storage::Streams::IInputStream const& xpsStream) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContentFactory>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelSourceFileContentFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelTargetPackage
    {
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowObjectModelTargetPackage<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlConverter
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ConvertPdlAsync(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& printTicket, winrt::Windows::Storage::Streams::IInputStream const& inputStream, winrt::Windows::Storage::Streams::IOutputStream const& outputStream) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlConverter<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlConverter2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ConvertPdlAsync(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& printTicket, winrt::Windows::Storage::Streams::IInputStream const& inputStream, winrt::Windows::Storage::Streams::IOutputStream const& outputStream, winrt::Windows::Graphics::Printing::Workflow::PdlConversionHostBasedProcessingOperations const& hostBasedProcessingOperations) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlConverter2>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlConverter2<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlDataAvailableEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration) Configuration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJob) PrinterJob() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlSourceContent) SourceContent() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlDataAvailableEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlDataAvailableEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlModificationRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration) Configuration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJob) PrinterJob() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlSourceContent) SourceContent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUILauncher) UILauncher() const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream) CreateJobOnPrinter(param::hstring const& targetContentType) const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream) CreateJobOnPrinterWithAttributes(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const& jobAttributes, param::hstring const& targetContentType) const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream) CreateJobOnPrinterWithAttributesBuffer(winrt::Windows::Storage::Streams::IBuffer const& jobAttributesBuffer, param::hstring const& targetContentType) const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlConverter) GetPdlConverter(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlConversionType const& conversionType) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlModificationRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlModificationRequestedEventArgs2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream) CreateJobOnPrinterWithAttributes(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const& jobAttributes, param::hstring const& targetContentType, param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const& operationAttributes, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowAttributesMergePolicy const& jobAttributesMergePolicy, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowAttributesMergePolicy const& operationAttributesMergePolicy) const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPdlTargetStream) CreateJobOnPrinterWithAttributesBuffer(winrt::Windows::Storage::Streams::IBuffer const& jobAttributesBuffer, param::hstring const& targetContentType, winrt::Windows::Storage::Streams::IBuffer const& operationAttributesBuffer, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowAttributesMergePolicy const& jobAttributesMergePolicy, winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowAttributesMergePolicy const& operationAttributesMergePolicy) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlModificationRequestedEventArgs2>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlModificationRequestedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlSourceContent
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ContentType() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) GetInputStream() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) GetContentFileAsync() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlSourceContent>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlSourceContent<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlTargetStream
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) GetOutputStream() const;
        WINRT_IMPL_AUTO(void) CompleteStreamSubmission(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus const& status) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPdlTargetStream>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPdlTargetStream<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPrinterJob
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) JobId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppPrintDevice) Printer() const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowPrinterJobStatus) GetJobStatus() const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket) GetJobPrintTicket() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) GetJobAttributesAsBuffer(param::iterable<hstring> const& attributeNames) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>) GetJobAttributes(param::iterable<hstring> const& attributeNames) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppSetAttributesResult) SetJobAttributesFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& jobAttributesBuffer) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppSetAttributesResult) SetJobAttributes(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const& jobAttributes) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowPrinterJob>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowPrinterJob<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSourceContent
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>) GetJobPrintTicketAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent) GetSourceSpoolDataAsStreamContent() const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent) GetSourceSpoolDataAsXpsObjectModel() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSourceContent<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSpoolStreamContent
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) GetInputStream() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSpoolStreamContent<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowStreamTarget
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) GetOutputStream() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowStreamTarget<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation) Operation() const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTarget) GetTarget(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& jobPrintTicket) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedOperation
    {
        WINRT_IMPL_AUTO(void) Complete(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus const& status) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration) Configuration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent) XpsContent() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedOperation<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTarget
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget) TargetAsStream() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage) TargetAsXpsObjectModelPackage() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTarget<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession) PrintWorkflowSession() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowUIActivatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession) PrintWorkflowSession() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowUIActivatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowUILauncher
    {
        WINRT_IMPL_AUTO(bool) IsUILaunchEnabled() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUICompletionStatus>) LaunchAndCompleteUIAsync() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUILauncher>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowUILauncher<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowXpsDataAvailableEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation) Operation() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>
    {
        template <typename D> using type = consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowXpsDataAvailableEventArgs<D>;
    };
}
#endif
