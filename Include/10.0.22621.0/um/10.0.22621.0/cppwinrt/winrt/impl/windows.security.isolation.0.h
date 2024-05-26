// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Isolation_0_H
#define WINRT_Windows_Security_Isolation_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct HResult;
    struct IAsyncAction;
    template <typename TResult, typename TProgress> struct __declspec(empty_bases) IAsyncOperationWithProgress;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Security::Isolation
{
    enum class IsolatedWindowsEnvironmentActivator : int32_t
    {
        System = 0,
        User = 1,
    };
    enum class IsolatedWindowsEnvironmentAllowedClipboardFormats : uint32_t
    {
        None = 0,
        Text = 0x1,
        Image = 0x2,
        Rtf = 0x4,
    };
    enum class IsolatedWindowsEnvironmentAvailablePrinters : uint32_t
    {
        None = 0,
        Local = 0x1,
        Network = 0x2,
        SystemPrintToPdf = 0x4,
        SystemPrintToXps = 0x8,
    };
    enum class IsolatedWindowsEnvironmentClipboardCopyPasteDirections : uint32_t
    {
        None = 0,
        HostToIsolatedWindowsEnvironment = 0x1,
        IsolatedWindowsEnvironmentToHost = 0x2,
    };
    enum class IsolatedWindowsEnvironmentCreateStatus : int32_t
    {
        Success = 0,
        FailureByPolicy = 1,
        UnknownFailure = 2,
    };
    enum class IsolatedWindowsEnvironmentCreationPriority : int32_t
    {
        Low = 0,
        Normal = 1,
    };
    enum class IsolatedWindowsEnvironmentHostError : int32_t
    {
        AdminPolicyIsDisabledOrNotPresent = 0,
        FeatureNotInstalled = 1,
        HardwareRequirementsNotMet = 2,
        RebootRequired = 3,
        UnknownError = 4,
    };
    enum class IsolatedWindowsEnvironmentLaunchFileStatus : int32_t
    {
        Success = 0,
        UnknownFailure = 1,
        EnvironmentUnavailable = 2,
        FileNotFound = 3,
        TimedOut = 4,
        AlreadySharedWithConflictingOptions = 5,
    };
    enum class IsolatedWindowsEnvironmentOwnerRegistrationStatus : int32_t
    {
        Success = 0,
        InvalidArgument = 1,
        AccessDenied = 2,
        InsufficientMemory = 3,
        UnknownFailure = 4,
    };
    enum class IsolatedWindowsEnvironmentPostMessageStatus : int32_t
    {
        Success = 0,
        UnknownFailure = 1,
        EnvironmentUnavailable = 2,
    };
    enum class IsolatedWindowsEnvironmentProcessState : int32_t
    {
        Running = 1,
        Aborted = 2,
        Completed = 3,
    };
    enum class IsolatedWindowsEnvironmentProgressState : int32_t
    {
        Queued = 0,
        Processing = 1,
        Completed = 2,
        Creating = 3,
        Retrying = 4,
        Starting = 5,
        Finalizing = 6,
    };
    enum class IsolatedWindowsEnvironmentShareFileStatus : int32_t
    {
        Success = 0,
        UnknownFailure = 1,
        EnvironmentUnavailable = 2,
        AlreadySharedWithConflictingOptions = 3,
        FileNotFound = 4,
        AccessDenied = 5,
    };
    enum class IsolatedWindowsEnvironmentShareFolderStatus : int32_t
    {
        Success = 0,
        UnknownFailure = 1,
        EnvironmentUnavailable = 2,
        FolderNotFound = 3,
        AccessDenied = 4,
    };
    enum class IsolatedWindowsEnvironmentSignInProgress : int32_t
    {
        Connecting = 0,
        Connected = 1,
        Authenticating = 2,
        SettingUpAccount = 3,
        Finalizing = 4,
        Completed = 5,
    };
    enum class IsolatedWindowsEnvironmentStartProcessStatus : int32_t
    {
        Success = 0,
        UnknownFailure = 1,
        EnvironmentUnavailable = 2,
        FileNotFound = 3,
        AppNotRegistered = 4,
    };
    struct IIsolatedWindowsEnvironment;
    struct IIsolatedWindowsEnvironment2;
    struct IIsolatedWindowsEnvironment3;
    struct IIsolatedWindowsEnvironment4;
    struct IIsolatedWindowsEnvironmentCreateResult;
    struct IIsolatedWindowsEnvironmentCreateResult2;
    struct IIsolatedWindowsEnvironmentFactory;
    struct IIsolatedWindowsEnvironmentFile;
    struct IIsolatedWindowsEnvironmentFile2;
    struct IIsolatedWindowsEnvironmentHostStatics;
    struct IIsolatedWindowsEnvironmentLaunchFileResult;
    struct IIsolatedWindowsEnvironmentOptions;
    struct IIsolatedWindowsEnvironmentOptions2;
    struct IIsolatedWindowsEnvironmentOptions3;
    struct IIsolatedWindowsEnvironmentOwnerRegistrationData;
    struct IIsolatedWindowsEnvironmentOwnerRegistrationResult;
    struct IIsolatedWindowsEnvironmentOwnerRegistrationStatics;
    struct IIsolatedWindowsEnvironmentPostMessageResult;
    struct IIsolatedWindowsEnvironmentProcess;
    struct IIsolatedWindowsEnvironmentShareFileRequestOptions;
    struct IIsolatedWindowsEnvironmentShareFileResult;
    struct IIsolatedWindowsEnvironmentShareFolderRequestOptions;
    struct IIsolatedWindowsEnvironmentShareFolderResult;
    struct IIsolatedWindowsEnvironmentStartProcessResult;
    struct IIsolatedWindowsEnvironmentTelemetryParameters;
    struct IIsolatedWindowsEnvironmentUserInfo;
    struct IIsolatedWindowsEnvironmentUserInfo2;
    struct IIsolatedWindowsHostMessengerStatics;
    struct IIsolatedWindowsHostMessengerStatics2;
    struct IsolatedWindowsEnvironment;
    struct IsolatedWindowsEnvironmentCreateResult;
    struct IsolatedWindowsEnvironmentFile;
    struct IsolatedWindowsEnvironmentHost;
    struct IsolatedWindowsEnvironmentLaunchFileResult;
    struct IsolatedWindowsEnvironmentOptions;
    struct IsolatedWindowsEnvironmentOwnerRegistration;
    struct IsolatedWindowsEnvironmentOwnerRegistrationData;
    struct IsolatedWindowsEnvironmentOwnerRegistrationResult;
    struct IsolatedWindowsEnvironmentPostMessageResult;
    struct IsolatedWindowsEnvironmentProcess;
    struct IsolatedWindowsEnvironmentShareFileRequestOptions;
    struct IsolatedWindowsEnvironmentShareFileResult;
    struct IsolatedWindowsEnvironmentShareFolderRequestOptions;
    struct IsolatedWindowsEnvironmentShareFolderResult;
    struct IsolatedWindowsEnvironmentStartProcessResult;
    struct IsolatedWindowsEnvironmentTelemetryParameters;
    struct IsolatedWindowsEnvironmentUserInfo;
    struct IsolatedWindowsHostMessenger;
    struct IsolatedWindowsEnvironmentCreateProgress;
    struct HostMessageReceivedCallback;
    struct MessageReceivedCallback;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHost>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistration>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsHostMessenger>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHostError>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcessState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProgressState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentSignInProgress>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>{ using type = struct_category<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProgressState, uint32_t>; };
    template <> struct category<winrt::Windows::Security::Isolation::HostMessageReceivedCallback>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::Security::Isolation::MessageReceivedCallback>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment> = L"Windows.Security.Isolation.IsolatedWindowsEnvironment";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentCreateResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentFile";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHost> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentHost";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentLaunchFileResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistration> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentOwnerRegistration";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentOwnerRegistrationData";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentOwnerRegistrationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentPostMessageResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentProcess";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentShareFileRequestOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentShareFileResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentShareFolderRequestOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentShareFolderResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentStartProcessResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentTelemetryParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentUserInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsHostMessenger> = L"Windows.Security.Isolation.IsolatedWindowsHostMessenger";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentActivator";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentAllowedClipboardFormats";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentAvailablePrinters";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentClipboardCopyPasteDirections";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateStatus> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentCreateStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentCreationPriority";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHostError> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentHostError";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileStatus> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentLaunchFileStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationStatus> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentOwnerRegistrationStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageStatus> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentPostMessageStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcessState> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentProcessState";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProgressState> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentProgressState";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileStatus> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentShareFileStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderStatus> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentShareFolderStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentSignInProgress> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentSignInProgress";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessStatus> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentStartProcessStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress> = L"Windows.Security.Isolation.IsolatedWindowsEnvironmentCreateProgress";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironment";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironment2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironment3";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironment4";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentCreateResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentCreateResult2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentFile";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentFile2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentHostStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentLaunchFileResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentOptions2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentOptions3";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentOwnerRegistrationData";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentOwnerRegistrationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentOwnerRegistrationStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentPostMessageResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentProcess";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentShareFileRequestOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentShareFileResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentShareFolderRequestOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentShareFolderResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentStartProcessResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentTelemetryParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentUserInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2> = L"Windows.Security.Isolation.IIsolatedWindowsEnvironmentUserInfo2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics> = L"Windows.Security.Isolation.IIsolatedWindowsHostMessengerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2> = L"Windows.Security.Isolation.IIsolatedWindowsHostMessengerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::HostMessageReceivedCallback> = L"Windows.Security.Isolation.HostMessageReceivedCallback";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::Isolation::MessageReceivedCallback> = L"Windows.Security.Isolation.MessageReceivedCallback";
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment>{ 0x41D24597,0xC328,0x4467,{ 0xB3,0x7F,0x4D,0xFC,0x6F,0x60,0xB6,0xBC } }; // 41D24597-C328-4467-B37F-4DFC6F60B6BC
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2>{ 0x2D365F39,0x88BD,0x4AB4,{ 0x93,0xCF,0x7E,0x2B,0xCE,0xF3,0x37,0xC0 } }; // 2D365F39-88BD-4AB4-93CF-7E2BCEF337C0
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3>{ 0xCB7FC7D2,0xD06E,0x4C26,{ 0x8A,0xDA,0xDA,0xCD,0xAA,0xAD,0x03,0xF5 } }; // CB7FC7D2-D06E-4C26-8ADA-DACDAAAD03F5
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4>{ 0x11E3701A,0xDD9E,0x4F1B,{ 0x81,0x2C,0x40,0x20,0xF3,0x07,0xF9,0x3C } }; // 11E3701A-DD9E-4F1B-812C-4020F307F93C
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult>{ 0xEF9A5E58,0xDCD7,0x45C2,{ 0x9C,0x85,0xAB,0x64,0x2A,0x71,0x5E,0x8E } }; // EF9A5E58-DCD7-45C2-9C85-AB642A715E8E
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2>{ 0xA547DBC7,0x61D4,0x4FB8,{ 0xAB,0x5C,0xED,0xEF,0xA3,0xD3,0x88,0xAD } }; // A547DBC7-61D4-4FB8-AB5C-EDEFA3D388AD
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory>{ 0x1ACA93E7,0xE804,0x454D,{ 0x84,0x66,0xF9,0x89,0x7C,0x20,0xB0,0xF6 } }; // 1ACA93E7-E804-454D-8466-F9897C20B0F6
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile>{ 0x4D5AE1EF,0x029F,0x4101,{ 0x8C,0x35,0xFE,0x91,0xBF,0x9C,0xD5,0xF0 } }; // 4D5AE1EF-029F-4101-8C35-FE91BF9CD5F0
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2>{ 0x4EEB8DEC,0xAD5D,0x4B0A,{ 0xB7,0x54,0xF3,0x6C,0x3D,0x46,0xD6,0x84 } }; // 4EEB8DEC-AD5D-4B0A-B754-F36C3D46D684
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics>{ 0x2C0E22C7,0x05A0,0x517A,{ 0xB8,0x1C,0x6E,0xE8,0x79,0x0C,0x38,0x1F } }; // 2C0E22C7-05A0-517A-B81C-6EE8790C381F
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult>{ 0x685D4176,0xF6E0,0x4569,{ 0xB1,0xAA,0x21,0x5C,0x0F,0xF5,0xB2,0x57 } }; // 685D4176-F6E0-4569-B1AA-215C0FF5B257
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions>{ 0xB71D98F7,0x61F0,0x4008,{ 0xB2,0x07,0x0B,0xF9,0xEB,0x2D,0x76,0xF2 } }; // B71D98F7-61F0-4008-B207-0BF9EB2D76F2
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2>{ 0x10D7CC31,0x8B8F,0x4B9D,{ 0xB2,0x2C,0x61,0x71,0x03,0xB5,0x5B,0x08 } }; // 10D7CC31-8B8F-4B9D-B22C-617103B55B08
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3>{ 0x98D5AA23,0x161F,0x4CD9,{ 0x8A,0x9C,0x26,0x9B,0x30,0x12,0x2B,0x0D } }; // 98D5AA23-161F-4CD9-8A9C-269B30122B0D
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData>{ 0xF888EC22,0xE8CF,0x56C0,{ 0xB1,0xDF,0x90,0xAF,0x4A,0xD8,0x0E,0x84 } }; // F888EC22-E8CF-56C0-B1DF-90AF4AD80E84
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult>{ 0x6DAB9451,0x6169,0x55DF,{ 0x8F,0x51,0x79,0x0E,0x99,0xD7,0x27,0x7D } }; // 6DAB9451-6169-55DF-8F51-790E99D7277D
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics>{ 0x10951754,0x204B,0x5EC9,{ 0x9D,0xE3,0xDF,0x79,0x2D,0x07,0x4A,0x61 } }; // 10951754-204B-5EC9-9DE3-DF792D074A61
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult>{ 0x0DFA28FA,0x2EF0,0x4D8F,{ 0xB3,0x41,0x31,0x71,0xB2,0xDF,0x93,0xB1 } }; // 0DFA28FA-2EF0-4D8F-B341-3171B2DF93B1
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess>{ 0xA858C3EF,0x8172,0x4F10,{ 0xAF,0x93,0xCB,0xE6,0x0A,0xF8,0x8D,0x09 } }; // A858C3EF-8172-4F10-AF93-CBE60AF88D09
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions>{ 0xC9190ED8,0x0FD0,0x4946,{ 0xBB,0x88,0x11,0x7A,0x60,0x73,0x7B,0x61 } }; // C9190ED8-0FD0-4946-BB88-117A60737B61
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult>{ 0xAEC7CAA7,0x9AC6,0x4BF5,{ 0x8B,0x91,0x5C,0x1A,0xDF,0x0D,0x7D,0x00 } }; // AEC7CAA7-9AC6-4BF5-8B91-5C1ADF0D7D00
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions>{ 0xC405EB7D,0x7053,0x4F6A,{ 0x9B,0x87,0x74,0x68,0x46,0xED,0x19,0xB2 } }; // C405EB7D-7053-4F6A-9B87-746846ED19B2
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult>{ 0x556BA72E,0xCA9D,0x4211,{ 0xB1,0x43,0x1C,0xED,0xC8,0x6E,0xB2,0xFE } }; // 556BA72E-CA9D-4211-B143-1CEDC86EB2FE
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult>{ 0x8FA1DC2F,0x57DA,0x4BB5,{ 0x9C,0x06,0xFA,0x07,0x2D,0x20,0x32,0xE2 } }; // 8FA1DC2F-57DA-4BB5-9C06-FA072D2032E2
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters>{ 0xEBDB3CAB,0x7A3A,0x4524,{ 0xA0,0xF4,0xF9,0x6E,0x28,0x4D,0x33,0xCD } }; // EBDB3CAB-7A3A-4524-A0F4-F96E284D33CD
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo>{ 0x8A9C75AE,0x69BA,0x4001,{ 0x96,0xFC,0x19,0xA0,0x27,0x03,0xB3,0x40 } }; // 8A9C75AE-69BA-4001-96FC-19A02703B340
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2>{ 0xB0BDD5DD,0x91D7,0x481E,{ 0x94,0xF2,0x2A,0x5A,0x6B,0xDF,0x93,0x83 } }; // B0BDD5DD-91D7-481E-94F2-2A5A6BDF9383
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics>{ 0x06E444BB,0x53C0,0x4889,{ 0x8F,0xA3,0x53,0x59,0x2E,0x37,0xCF,0x21 } }; // 06E444BB-53C0-4889-8FA3-53592E37CF21
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2>{ 0x55EF9EBC,0x0444,0x42AD,{ 0x83,0x2D,0x1B,0x89,0xC0,0x89,0xD1,0xCA } }; // 55EF9EBC-0444-42AD-832D-1B89C089D1CA
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::HostMessageReceivedCallback>{ 0xFAF26FFA,0x8CE1,0x4CC1,{ 0xB2,0x78,0x32,0x2D,0x31,0xA5,0xE4,0xA3 } }; // FAF26FFA-8CE1-4CC1-B278-322D31A5E4A3
    template <> inline constexpr guid guid_v<winrt::Windows::Security::Isolation::MessageReceivedCallback>{ 0xF5B4C8FF,0x1D9D,0x4995,{ 0x9F,0xEA,0x4D,0x15,0x25,0x7C,0x07,0x57 } }; // F5B4C8FF-1D9D-4995-9FEA-4D15257C0757
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters; };
    template <> struct default_interface<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo>{ using type = winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo; };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall StartProcessSilentlyAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall StartProcessSilentlyWithTelemetryAsync(void*, void*, int32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ShareFolderAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ShareFolderWithTelemetryAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall LaunchFileWithUIAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall LaunchFileWithUIAndTelemetryAsync(void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall TerminateAsync(void**) noexcept = 0;
            virtual int32_t __stdcall TerminateWithTelemetryAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RegisterMessageReceiver(winrt::guid, void*) noexcept = 0;
            virtual int32_t __stdcall UnregisterMessageReceiver(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall PostMessageToReceiverAsync(winrt::guid, void*, void**) noexcept = 0;
            virtual int32_t __stdcall PostMessageToReceiverWithTelemetryAsync(winrt::guid, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetUserInfo(void**) noexcept = 0;
            virtual int32_t __stdcall ShareFileAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ShareFileWithTelemetryAsync(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ChangePriority(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall get_Environment(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ChangeCreationPriority(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithTelemetryAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetById(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindByOwnerId(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_HostPath(void**) noexcept = 0;
            virtual int32_t __stdcall Close() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_GuestPath(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsReadOnly(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsReady(bool*) noexcept = 0;
            virtual int32_t __stdcall get_HostErrors(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall get_File(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EnvironmentOwnerId(void**) noexcept = 0;
            virtual int32_t __stdcall put_EnvironmentOwnerId(void*) noexcept = 0;
            virtual int32_t __stdcall get_AllowedClipboardFormats(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AllowedClipboardFormats(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ClipboardCopyPasteDirections(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ClipboardCopyPasteDirections(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_AvailablePrinters(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AvailablePrinters(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_SharedHostFolderPath(void**) noexcept = 0;
            virtual int32_t __stdcall get_SharedFolderNameInEnvironment(void**) noexcept = 0;
            virtual int32_t __stdcall ShareHostFolderForUntrustedItems(void*, void*) noexcept = 0;
            virtual int32_t __stdcall get_PersistUserProfile(bool*) noexcept = 0;
            virtual int32_t __stdcall put_PersistUserProfile(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllowGraphicsHardwareAcceleration(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowGraphicsHardwareAcceleration(bool) noexcept = 0;
            virtual int32_t __stdcall get_AllowCameraAndMicrophoneAccess(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowCameraAndMicrophoneAccess(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_WindowAnnotationOverride(void**) noexcept = 0;
            virtual int32_t __stdcall put_WindowAnnotationOverride(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowedClipboardFormatsToEnvironment(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AllowedClipboardFormatsToEnvironment(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_AllowedClipboardFormatsToHost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_AllowedClipboardFormatsToHost(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_CreationPriority(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CreationPriority(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ShareableFolders(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProcessesRunnableAsSystem(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProcessesRunnableAsUser(void**) noexcept = 0;
            virtual int32_t __stdcall get_ActivationFileExtensions(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Register(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall Unregister(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExitCode(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall WaitForExit() noexcept = 0;
            virtual int32_t __stdcall WaitForExitWithTimeout(uint32_t) noexcept = 0;
            virtual int32_t __stdcall WaitForExitAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowWrite(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowWrite(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall get_File(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowWrite(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowWrite(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall get_Process(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CorrelationId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_CorrelationId(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EnvironmentUserSid(void**) noexcept = 0;
            virtual int32_t __stdcall get_EnvironmentUserName(void**) noexcept = 0;
            virtual int32_t __stdcall TryWaitForSignInAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryWaitForSignInWithProgressAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall PostMessageToReceiver(winrt::guid, void*) noexcept = 0;
            virtual int32_t __stdcall GetFileId(void*, winrt::guid*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RegisterHostMessageReceiver(winrt::guid, void*) noexcept = 0;
            virtual int32_t __stdcall UnregisterHostMessageReceiver(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::HostMessageReceivedCallback>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(winrt::guid, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::Isolation::MessageReceivedCallback>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(winrt::guid, void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>) StartProcessSilentlyAsync(param::hstring const& hostExePath, param::hstring const& arguments, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator const& activator) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessResult>) StartProcessSilentlyAsync(param::hstring const& hostExePath, param::hstring const& arguments, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentActivator const& activator, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>) ShareFolderAsync(param::hstring const& hostFolder, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions const& requestOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderResult>) ShareFolderAsync(param::hstring const& hostFolder, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderRequestOptions const& requestOptions, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>) LaunchFileWithUIAsync(param::hstring const& appExePath, param::hstring const& argumentsTemplate, param::hstring const& filePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileResult>) LaunchFileWithUIAsync(param::hstring const& appExePath, param::hstring const& argumentsTemplate, param::hstring const& filePath, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) TerminateAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) TerminateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const;
        WINRT_IMPL_AUTO(void) RegisterMessageReceiver(winrt::guid const& receiverId, winrt::Windows::Security::Isolation::MessageReceivedCallback const& messageReceivedCallback) const;
        WINRT_IMPL_AUTO(void) UnregisterMessageReceiver(winrt::guid const& receiverId) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>) PostMessageToReceiverAsync(winrt::guid const& receiverId, param::async_iterable<winrt::Windows::Foundation::IInspectable> const& message) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageResult>) PostMessageToReceiverAsync(winrt::guid const& receiverId, param::async_iterable<winrt::Windows::Foundation::IInspectable> const& message, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentUserInfo) GetUserInfo() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>) ShareFileAsync(param::hstring const& filePath, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileResult>) ShareFileAsync(param::hstring const& filePath, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileRequestOptions const& options, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment3<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment4
    {
        WINRT_IMPL_AUTO(void) ChangePriority(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const& Priority) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironment4<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment) Environment() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult2
    {
        WINRT_IMPL_AUTO(void) ChangeCreationPriority(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const& priority) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentCreateResult2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>) CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>) CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment) GetById(param::hstring const& environmentId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironment>) FindByOwnerId(param::hstring const& environmentOwnerId) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFactory>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) HostPath() const;
        WINRT_IMPL_AUTO(void) Close() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) GuestPath() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReadOnly() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentFile2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentHostStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReady() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentHostError>) HostErrors() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentHostStatics>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentHostStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentLaunchFileResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentLaunchFileStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile) File() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentLaunchFileResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EnvironmentOwnerId() const;
        WINRT_IMPL_AUTO(void) EnvironmentOwnerId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats) AllowedClipboardFormats() const;
        WINRT_IMPL_AUTO(void) AllowedClipboardFormats(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections) ClipboardCopyPasteDirections() const;
        WINRT_IMPL_AUTO(void) ClipboardCopyPasteDirections(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentClipboardCopyPasteDirections const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters) AvailablePrinters() const;
        WINRT_IMPL_AUTO(void) AvailablePrinters(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAvailablePrinters const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SharedHostFolderPath() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SharedFolderNameInEnvironment() const;
        WINRT_IMPL_AUTO(void) ShareHostFolderForUntrustedItems(param::hstring const& SharedHostFolderPath, param::hstring const& ShareFolderNameInEnvironment) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) PersistUserProfile() const;
        WINRT_IMPL_AUTO(void) PersistUserProfile(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowGraphicsHardwareAcceleration() const;
        WINRT_IMPL_AUTO(void) AllowGraphicsHardwareAcceleration(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowCameraAndMicrophoneAccess() const;
        WINRT_IMPL_AUTO(void) AllowCameraAndMicrophoneAccess(bool value) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) WindowAnnotationOverride() const;
        WINRT_IMPL_AUTO(void) WindowAnnotationOverride(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats) AllowedClipboardFormatsToEnvironment() const;
        WINRT_IMPL_AUTO(void) AllowedClipboardFormatsToEnvironment(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats) AllowedClipboardFormatsToHost() const;
        WINRT_IMPL_AUTO(void) AllowedClipboardFormatsToHost(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentAllowedClipboardFormats const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority) CreationPriority() const;
        WINRT_IMPL_AUTO(void) CreationPriority(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentCreationPriority const& value) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOptions3<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) ShareableFolders() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) ProcessesRunnableAsSystem() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) ProcessesRunnableAsUser() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) ActivationFileExtensions() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationData<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationResult) Register(param::hstring const& ownerName, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData const& ownerRegistrationData) const;
        WINRT_IMPL_AUTO(void) Unregister(param::hstring const& ownerName) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationStatics>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentOwnerRegistrationStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentPostMessageResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentPostMessageStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentPostMessageResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentProcess
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcessState) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExitCode() const;
        WINRT_IMPL_AUTO(void) WaitForExit() const;
        WINRT_IMPL_AUTO(void) WaitForExitWithTimeout(uint32_t timeoutMilliseconds) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WaitForExitAsync() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentProcess<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileRequestOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowWrite() const;
        WINRT_IMPL_AUTO(void) AllowWrite(bool value) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileRequestOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFileStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentFile) File() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFileResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderRequestOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowWrite() const;
        WINRT_IMPL_AUTO(void) AllowWrite(bool value) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderRequestOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentShareFolderStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentShareFolderResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentStartProcessResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentStartProcessStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProcess) Process() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentStartProcessResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentTelemetryParameters
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) CorrelationId() const;
        WINRT_IMPL_AUTO(void) CorrelationId(winrt::guid const& value) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentTelemetryParameters<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EnvironmentUserSid() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EnvironmentUserName() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryWaitForSignInAsync() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<bool, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentSignInProgress>) TryWaitForSignInWithProgressAsync() const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsEnvironmentUserInfo2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics
    {
        WINRT_IMPL_AUTO(void) PostMessageToReceiver(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message) const;
        WINRT_IMPL_AUTO(winrt::guid) GetFileId(param::hstring const& filePath) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics2
    {
        WINRT_IMPL_AUTO(void) RegisterHostMessageReceiver(winrt::guid const& receiverId, winrt::Windows::Security::Isolation::HostMessageReceivedCallback const& hostMessageReceivedCallback) const;
        WINRT_IMPL_AUTO(void) UnregisterHostMessageReceiver(winrt::guid const& receiverId) const;
    };
    template <> struct consume<winrt::Windows::Security::Isolation::IIsolatedWindowsHostMessengerStatics2>
    {
        template <typename D> using type = consume_Windows_Security_Isolation_IIsolatedWindowsHostMessengerStatics2<D>;
    };
    struct struct_Windows_Security_Isolation_IsolatedWindowsEnvironmentCreateProgress
    {
        int32_t State;
        uint32_t PercentComplete;
    };
    template <> struct abi<Windows::Security::Isolation::IsolatedWindowsEnvironmentCreateProgress>
    {
        using type = struct_Windows_Security_Isolation_IsolatedWindowsEnvironmentCreateProgress;
    };
}
#endif
