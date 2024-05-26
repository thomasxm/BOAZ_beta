// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Update_0_H
#define WINRT_Windows_Management_Update_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct HResult;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
    struct ValueSet;
}
WINRT_EXPORT namespace winrt::Windows::Management::Update
{
    enum class WindowsUpdateAdministratorOptions : uint32_t
    {
        None = 0,
        RequireAdministratorApprovalForScans = 0x1,
        RequireAdministratorApprovalForUpdates = 0x2,
        RequireAdministratorApprovalForActions = 0x4,
    };
    enum class WindowsUpdateAdministratorStatus : int32_t
    {
        Succeeded = 0,
        NoAdministratorRegistered = 1,
        OtherAdministratorIsRegistered = 2,
    };
    enum class WindowsUpdateAttentionRequiredReason : int32_t
    {
        None = 0,
        SeekerUpdate = 1,
        ReadyToReboot = 2,
        NeedNonMeteredNetwork = 3,
        NeedUserAgreementForMeteredNetwork = 4,
        NeedNetwork = 5,
        NeedMoreSpace = 6,
        BatterySaverEnabled = 7,
        NeedUserInteraction = 8,
        NeedUserAgreementForPolicy = 9,
        CompatibilityError = 10,
        NeedUserInteractionForEula = 11,
        NeedUserInteractionForCta = 12,
        Regulated = 13,
        ExternalReboot = 14,
        OtherUpdate = 15,
        BlockedByProvider = 16,
        BlockedByPostRebootFailure = 17,
        UserEngaged = 18,
        BlockedByBattery = 19,
        Exclusivity = 20,
        BlockedBySerialization = 21,
        ConflictClass = 22,
        BlockedByAdminApproval = 23,
        BlockedByTooManyAttempts = 24,
        BlockedByFailure = 25,
        Demotion = 26,
        BlockedByActiveHours = 27,
        ScheduledForMaintenance = 28,
        PolicyScheduledInstallTime = 29,
        BlockedByOobe = 30,
        DeferredDuringOobe = 31,
        DeferredForSustainableTime = 32,
    };
    struct IPreviewBuildsManager;
    struct IPreviewBuildsManagerStatics;
    struct IPreviewBuildsState;
    struct IWindowsUpdate;
    struct IWindowsUpdateActionCompletedEventArgs;
    struct IWindowsUpdateActionProgress;
    struct IWindowsUpdateActionResult;
    struct IWindowsUpdateAdministrator;
    struct IWindowsUpdateAdministratorStatics;
    struct IWindowsUpdateApprovalData;
    struct IWindowsUpdateAttentionRequiredInfo;
    struct IWindowsUpdateAttentionRequiredReasonChangedEventArgs;
    struct IWindowsUpdateGetAdministratorResult;
    struct IWindowsUpdateItem;
    struct IWindowsUpdateManager;
    struct IWindowsUpdateManagerFactory;
    struct IWindowsUpdateProgressChangedEventArgs;
    struct IWindowsUpdateRestartRequestOptions;
    struct IWindowsUpdateRestartRequestOptionsFactory;
    struct IWindowsUpdateScanCompletedEventArgs;
    struct PreviewBuildsManager;
    struct PreviewBuildsState;
    struct WindowsUpdate;
    struct WindowsUpdateActionCompletedEventArgs;
    struct WindowsUpdateActionProgress;
    struct WindowsUpdateActionResult;
    struct WindowsUpdateAdministrator;
    struct WindowsUpdateApprovalData;
    struct WindowsUpdateAttentionRequiredInfo;
    struct WindowsUpdateAttentionRequiredReasonChangedEventArgs;
    struct WindowsUpdateGetAdministratorResult;
    struct WindowsUpdateItem;
    struct WindowsUpdateManager;
    struct WindowsUpdateProgressChangedEventArgs;
    struct WindowsUpdateRestartRequestOptions;
    struct WindowsUpdateScanCompletedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Management::Update::IPreviewBuildsManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IPreviewBuildsManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IPreviewBuildsState>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdate>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateActionCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateActionProgress>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateActionResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateAdministrator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateAdministratorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateApprovalData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredReasonChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateGetAdministratorResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateManagerFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateProgressChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptionsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::IWindowsUpdateScanCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Update::PreviewBuildsManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::PreviewBuildsState>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdate>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateActionCompletedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateActionProgress>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateActionResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateAdministrator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateApprovalData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReasonChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateGetAdministratorResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateProgressChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateRestartRequestOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateScanCompletedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateAdministratorOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateAdministratorStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReason>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::PreviewBuildsManager> = L"Windows.Management.Update.PreviewBuildsManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::PreviewBuildsState> = L"Windows.Management.Update.PreviewBuildsState";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdate> = L"Windows.Management.Update.WindowsUpdate";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateActionCompletedEventArgs> = L"Windows.Management.Update.WindowsUpdateActionCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateActionProgress> = L"Windows.Management.Update.WindowsUpdateActionProgress";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateActionResult> = L"Windows.Management.Update.WindowsUpdateActionResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateAdministrator> = L"Windows.Management.Update.WindowsUpdateAdministrator";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateApprovalData> = L"Windows.Management.Update.WindowsUpdateApprovalData";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredInfo> = L"Windows.Management.Update.WindowsUpdateAttentionRequiredInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReasonChangedEventArgs> = L"Windows.Management.Update.WindowsUpdateAttentionRequiredReasonChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateGetAdministratorResult> = L"Windows.Management.Update.WindowsUpdateGetAdministratorResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateItem> = L"Windows.Management.Update.WindowsUpdateItem";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateManager> = L"Windows.Management.Update.WindowsUpdateManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateProgressChangedEventArgs> = L"Windows.Management.Update.WindowsUpdateProgressChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateRestartRequestOptions> = L"Windows.Management.Update.WindowsUpdateRestartRequestOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateScanCompletedEventArgs> = L"Windows.Management.Update.WindowsUpdateScanCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateAdministratorOptions> = L"Windows.Management.Update.WindowsUpdateAdministratorOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateAdministratorStatus> = L"Windows.Management.Update.WindowsUpdateAdministratorStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReason> = L"Windows.Management.Update.WindowsUpdateAttentionRequiredReason";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IPreviewBuildsManager> = L"Windows.Management.Update.IPreviewBuildsManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IPreviewBuildsManagerStatics> = L"Windows.Management.Update.IPreviewBuildsManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IPreviewBuildsState> = L"Windows.Management.Update.IPreviewBuildsState";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdate> = L"Windows.Management.Update.IWindowsUpdate";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateActionCompletedEventArgs> = L"Windows.Management.Update.IWindowsUpdateActionCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateActionProgress> = L"Windows.Management.Update.IWindowsUpdateActionProgress";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateActionResult> = L"Windows.Management.Update.IWindowsUpdateActionResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateAdministrator> = L"Windows.Management.Update.IWindowsUpdateAdministrator";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateAdministratorStatics> = L"Windows.Management.Update.IWindowsUpdateAdministratorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateApprovalData> = L"Windows.Management.Update.IWindowsUpdateApprovalData";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredInfo> = L"Windows.Management.Update.IWindowsUpdateAttentionRequiredInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredReasonChangedEventArgs> = L"Windows.Management.Update.IWindowsUpdateAttentionRequiredReasonChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateGetAdministratorResult> = L"Windows.Management.Update.IWindowsUpdateGetAdministratorResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateItem> = L"Windows.Management.Update.IWindowsUpdateItem";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateManager> = L"Windows.Management.Update.IWindowsUpdateManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateManagerFactory> = L"Windows.Management.Update.IWindowsUpdateManagerFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateProgressChangedEventArgs> = L"Windows.Management.Update.IWindowsUpdateProgressChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptions> = L"Windows.Management.Update.IWindowsUpdateRestartRequestOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptionsFactory> = L"Windows.Management.Update.IWindowsUpdateRestartRequestOptionsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Update::IWindowsUpdateScanCompletedEventArgs> = L"Windows.Management.Update.IWindowsUpdateScanCompletedEventArgs";
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IPreviewBuildsManager>{ 0xFA07DD61,0x7E4F,0x59F7,{ 0x7C,0x9F,0xDE,0xF9,0x05,0x1C,0x5F,0x62 } }; // FA07DD61-7E4F-59F7-7C9F-DEF9051C5F62
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IPreviewBuildsManagerStatics>{ 0x3E422887,0xB112,0x5A70,{ 0x7D,0xA1,0x97,0xD7,0x8D,0x32,0xAA,0x29 } }; // 3E422887-B112-5A70-7DA1-97D78D32AA29
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IPreviewBuildsState>{ 0xA2F2903E,0xB223,0x5F63,{ 0x75,0x46,0x3E,0x8E,0xAC,0x07,0x0A,0x2E } }; // A2F2903E-B223-5F63-7546-3E8EAC070A2E
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdate>{ 0xC3C88DD7,0x0EF3,0x52B2,{ 0xA9,0xAD,0x66,0xBF,0xC6,0xBD,0x95,0x82 } }; // C3C88DD7-0EF3-52B2-A9AD-66BFC6BD9582
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateActionCompletedEventArgs>{ 0x2C44B950,0xA655,0x5321,{ 0xAE,0xC1,0xAE,0xE7,0x62,0x92,0x21,0x31 } }; // 2C44B950-A655-5321-AEC1-AEE762922131
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateActionProgress>{ 0x83B22D8A,0x4BB0,0x549F,{ 0xBA,0x39,0x59,0x72,0x48,0x82,0xD1,0x37 } }; // 83B22D8A-4BB0-549F-BA39-59724882D137
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateActionResult>{ 0xE6692C62,0xF697,0x51B7,{ 0xAB,0x7F,0xE7,0x3E,0x5E,0x68,0x8F,0x12 } }; // E6692C62-F697-51B7-AB7F-E73E5E688F12
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateAdministrator>{ 0x7A60181C,0xBA1E,0x5CF9,{ 0xAA,0x65,0x30,0x41,0x20,0xB7,0x3D,0x72 } }; // 7A60181C-BA1E-5CF9-AA65-304120B73D72
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateAdministratorStatics>{ 0x013E6D36,0xEF69,0x53BC,{ 0x8D,0xB8,0xC4,0x03,0xBC,0xA5,0x50,0xED } }; // 013E6D36-EF69-53BC-8DB8-C403BCA550ED
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateApprovalData>{ 0xAADF5BFD,0x84DB,0x59BC,{ 0x85,0xE2,0xAD,0x4F,0xC1,0xF6,0x2F,0x7C } }; // AADF5BFD-84DB-59BC-85E2-AD4FC1F62F7C
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredInfo>{ 0x44DF2579,0x74D3,0x5FFA,{ 0xB6,0xCE,0x09,0xE1,0x87,0xE1,0xE0,0xED } }; // 44DF2579-74D3-5FFA-B6CE-09E187E1E0ED
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredReasonChangedEventArgs>{ 0x0627ABCA,0xDBB8,0x524A,{ 0xB1,0xD2,0xD9,0xDF,0x00,0x4E,0xEB,0x31 } }; // 0627ABCA-DBB8-524A-B1D2-D9DF004EEB31
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateGetAdministratorResult>{ 0xBB39FFC4,0x2C42,0x5B1C,{ 0x89,0x95,0x34,0x33,0x41,0xC9,0x2C,0x50 } }; // BB39FFC4-2C42-5B1C-8995-343341C92C50
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateItem>{ 0xB222E44A,0x49B6,0x59BF,{ 0xA0,0x33,0xEF,0x61,0x7C,0xD7,0x3A,0x98 } }; // B222E44A-49B6-59BF-A033-EF617CD73A98
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateManager>{ 0x5DD966C0,0xA71A,0x5602,{ 0xBB,0xD0,0x09,0xA7,0x0E,0x45,0x73,0xFA } }; // 5DD966C0-A71A-5602-BBD0-09A70E4573FA
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateManagerFactory>{ 0x1B394DF8,0xDECB,0x5F44,{ 0xB4,0x7C,0x6C,0xCF,0x3B,0xCF,0xDB,0x37 } }; // 1B394DF8-DECB-5F44-B47C-6CCF3BCFDB37
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateProgressChangedEventArgs>{ 0xBBFBDEEB,0x94C8,0x5AA7,{ 0xB0,0xFB,0x66,0xC6,0x7C,0x23,0x3B,0x0A } }; // BBFBDEEB-94C8-5AA7-B0FB-66C67C233B0A
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptions>{ 0x38CFB7D3,0x4188,0x5222,{ 0x90,0x5C,0x6C,0x44,0x43,0xC9,0x51,0xEE } }; // 38CFB7D3-4188-5222-905C-6C4443C951EE
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptionsFactory>{ 0x75F41D04,0x0E17,0x50D0,{ 0x8C,0x15,0x6B,0x9D,0x05,0x39,0xB3,0xA9 } }; // 75F41D04-0E17-50D0-8C15-6B9D0539B3A9
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Update::IWindowsUpdateScanCompletedEventArgs>{ 0x95B6953E,0xBA5C,0x5FE8,{ 0xB1,0x15,0x12,0xDE,0x18,0x4A,0x6B,0xB0 } }; // 95B6953E-BA5C-5FE8-B115-12DE184A6BB0
    template <> struct default_interface<winrt::Windows::Management::Update::PreviewBuildsManager>{ using type = winrt::Windows::Management::Update::IPreviewBuildsManager; };
    template <> struct default_interface<winrt::Windows::Management::Update::PreviewBuildsState>{ using type = winrt::Windows::Management::Update::IPreviewBuildsState; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdate>{ using type = winrt::Windows::Management::Update::IWindowsUpdate; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateActionCompletedEventArgs>{ using type = winrt::Windows::Management::Update::IWindowsUpdateActionCompletedEventArgs; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateActionProgress>{ using type = winrt::Windows::Management::Update::IWindowsUpdateActionProgress; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateActionResult>{ using type = winrt::Windows::Management::Update::IWindowsUpdateActionResult; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateAdministrator>{ using type = winrt::Windows::Management::Update::IWindowsUpdateAdministrator; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateApprovalData>{ using type = winrt::Windows::Management::Update::IWindowsUpdateApprovalData; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredInfo>{ using type = winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredInfo; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReasonChangedEventArgs>{ using type = winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredReasonChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateGetAdministratorResult>{ using type = winrt::Windows::Management::Update::IWindowsUpdateGetAdministratorResult; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateItem>{ using type = winrt::Windows::Management::Update::IWindowsUpdateItem; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateManager>{ using type = winrt::Windows::Management::Update::IWindowsUpdateManager; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateProgressChangedEventArgs>{ using type = winrt::Windows::Management::Update::IWindowsUpdateProgressChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateRestartRequestOptions>{ using type = winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptions; };
    template <> struct default_interface<winrt::Windows::Management::Update::WindowsUpdateScanCompletedEventArgs>{ using type = winrt::Windows::Management::Update::IWindowsUpdateScanCompletedEventArgs; };
    template <> struct abi<winrt::Windows::Management::Update::IPreviewBuildsManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ArePreviewBuildsAllowed(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ArePreviewBuildsAllowed(bool) noexcept = 0;
            virtual int32_t __stdcall GetCurrentState(void**) noexcept = 0;
            virtual int32_t __stdcall SyncAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IPreviewBuildsManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
            virtual int32_t __stdcall IsSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IPreviewBuildsState>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdate>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProviderId(void**) noexcept = 0;
            virtual int32_t __stdcall get_UpdateId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsFeatureUpdate(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsMinorImpact(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSecurity(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCritical(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsForOS(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDriver(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsMandatory(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsUrgent(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSeeker(bool*) noexcept = 0;
            virtual int32_t __stdcall get_MoreInfoUrl(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportUrl(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsEulaAccepted(bool*) noexcept = 0;
            virtual int32_t __stdcall get_EulaText(void**) noexcept = 0;
            virtual int32_t __stdcall get_Deadline(void**) noexcept = 0;
            virtual int32_t __stdcall get_AttentionRequiredInfo(void**) noexcept = 0;
            virtual int32_t __stdcall get_ActionResult(void**) noexcept = 0;
            virtual int32_t __stdcall get_CurrentAction(void**) noexcept = 0;
            virtual int32_t __stdcall get_ActionProgress(void**) noexcept = 0;
            virtual int32_t __stdcall GetPropertyValue(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AcceptEula() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateActionCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Update(void**) noexcept = 0;
            virtual int32_t __stdcall get_Action(void**) noexcept = 0;
            virtual int32_t __stdcall get_Succeeded(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateActionProgress>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Action(void**) noexcept = 0;
            virtual int32_t __stdcall get_Progress(double*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateActionResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Succeeded(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall get_Action(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateAdministrator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall StartAdministratorScan() noexcept = 0;
            virtual int32_t __stdcall ApproveWindowsUpdateAction(void*, void*) noexcept = 0;
            virtual int32_t __stdcall RevokeWindowsUpdateActionApproval(void*, void*) noexcept = 0;
            virtual int32_t __stdcall ApproveWindowsUpdate(void*, void*) noexcept = 0;
            virtual int32_t __stdcall RevokeWindowsUpdateApproval(void*) noexcept = 0;
            virtual int32_t __stdcall GetUpdates(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateAdministratorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetRegisteredAdministrator(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RegisterForAdministration(void*, uint32_t, int32_t*) noexcept = 0;
            virtual int32_t __stdcall UnregisterForAdministration(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall GetRegisteredAdministratorName(void**) noexcept = 0;
            virtual int32_t __stdcall RequestRestart(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CancelRestartRequest(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateApprovalData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Seeker(void**) noexcept = 0;
            virtual int32_t __stdcall put_Seeker(void*) noexcept = 0;
            virtual int32_t __stdcall get_AllowDownloadOnMetered(void**) noexcept = 0;
            virtual int32_t __stdcall put_AllowDownloadOnMetered(void*) noexcept = 0;
            virtual int32_t __stdcall get_ComplianceDeadlineInDays(void**) noexcept = 0;
            virtual int32_t __stdcall put_ComplianceDeadlineInDays(void*) noexcept = 0;
            virtual int32_t __stdcall get_ComplianceGracePeriodInDays(void**) noexcept = 0;
            virtual int32_t __stdcall put_ComplianceGracePeriodInDays(void*) noexcept = 0;
            virtual int32_t __stdcall get_OptOutOfAutoReboot(void**) noexcept = 0;
            virtual int32_t __stdcall put_OptOutOfAutoReboot(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reason(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredReasonChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Update(void**) noexcept = 0;
            virtual int32_t __stdcall get_Reason(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateGetAdministratorResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Administrator(void**) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProviderId(void**) noexcept = 0;
            virtual int32_t __stdcall get_UpdateId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_MoreInfoUrl(void**) noexcept = 0;
            virtual int32_t __stdcall get_Category(void**) noexcept = 0;
            virtual int32_t __stdcall get_Operation(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_ScanningStateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ScanningStateChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_WorkingStateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_WorkingStateChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ProgressChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProgressChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AttentionRequiredReasonChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AttentionRequiredReasonChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ActionCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ActionCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ScanCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ScanCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_IsScanning(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsWorking(bool*) noexcept = 0;
            virtual int32_t __stdcall get_LastSuccessfulScanTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall GetApplicableUpdates(void**) noexcept = 0;
            virtual int32_t __stdcall GetMostRecentCompletedUpdates(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetMostRecentCompletedUpdatesAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall StartScan(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateManagerFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateProgressChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Update(void**) noexcept = 0;
            virtual int32_t __stdcall get_ActionProgress(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall put_Title(void*) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall put_Description(void*) noexcept = 0;
            virtual int32_t __stdcall get_MoreInfoUrl(void**) noexcept = 0;
            virtual int32_t __stdcall put_MoreInfoUrl(void*) noexcept = 0;
            virtual int32_t __stdcall get_ComplianceDeadlineInDays(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ComplianceDeadlineInDays(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ComplianceGracePeriodInDays(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ComplianceGracePeriodInDays(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_OrganizationName(void**) noexcept = 0;
            virtual int32_t __stdcall put_OrganizationName(void*) noexcept = 0;
            virtual int32_t __stdcall get_OptOutOfAutoReboot(bool*) noexcept = 0;
            virtual int32_t __stdcall put_OptOutOfAutoReboot(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptionsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void*, void*, int32_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Update::IWindowsUpdateScanCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProviderId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Succeeded(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall get_Updates(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Management_Update_IPreviewBuildsManager
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ArePreviewBuildsAllowed() const;
        WINRT_IMPL_AUTO(void) ArePreviewBuildsAllowed(bool value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Update::PreviewBuildsState) GetCurrentState() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) SyncAsync() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IPreviewBuildsManager>
    {
        template <typename D> using type = consume_Windows_Management_Update_IPreviewBuildsManager<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IPreviewBuildsManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Update::PreviewBuildsManager) GetDefault() const;
        WINRT_IMPL_AUTO(bool) IsSupported() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IPreviewBuildsManagerStatics>
    {
        template <typename D> using type = consume_Windows_Management_Update_IPreviewBuildsManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IPreviewBuildsState
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) Properties() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IPreviewBuildsState>
    {
        template <typename D> using type = consume_Windows_Management_Update_IPreviewBuildsState<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdate
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ProviderId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UpdateId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsFeatureUpdate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsMinorImpact() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSecurity() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCritical() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsForOS() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDriver() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsMandatory() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsUrgent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSeeker() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) MoreInfoUrl() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) SupportUrl() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEulaAccepted() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EulaText() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) Deadline() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredInfo) AttentionRequiredInfo() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateActionResult) ActionResult() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CurrentAction() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateActionProgress) ActionProgress() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) GetPropertyValue(param::hstring const& propertyName) const;
        WINRT_IMPL_AUTO(void) AcceptEula() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdate>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdate<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateActionCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdate) Update() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Action() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Succeeded() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateActionCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateActionCompletedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateActionProgress
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Action() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) Progress() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateActionProgress>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateActionProgress<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateActionResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Succeeded() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Action() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateActionResult>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateActionResult<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateAdministrator
    {
        WINRT_IMPL_AUTO(void) StartAdministratorScan() const;
        WINRT_IMPL_AUTO(void) ApproveWindowsUpdateAction(param::hstring const& updateId, param::hstring const& action) const;
        WINRT_IMPL_AUTO(void) RevokeWindowsUpdateActionApproval(param::hstring const& updateId, param::hstring const& action) const;
        WINRT_IMPL_AUTO(void) ApproveWindowsUpdate(param::hstring const& updateId, winrt::Windows::Management::Update::WindowsUpdateApprovalData const& approvalData) const;
        WINRT_IMPL_AUTO(void) RevokeWindowsUpdateApproval(param::hstring const& updateId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::Update::WindowsUpdate>) GetUpdates() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateAdministrator>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateAdministrator<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateAdministratorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateGetAdministratorResult) GetRegisteredAdministrator(param::hstring const& organizationName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateAdministratorStatus) RegisterForAdministration(param::hstring const& organizationName, winrt::Windows::Management::Update::WindowsUpdateAdministratorOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateAdministratorStatus) UnregisterForAdministration(param::hstring const& organizationName) const;
        WINRT_IMPL_AUTO(hstring) GetRegisteredAdministratorName() const;
        WINRT_IMPL_AUTO(hstring) RequestRestart(winrt::Windows::Management::Update::WindowsUpdateRestartRequestOptions const& restartOptions) const;
        WINRT_IMPL_AUTO(void) CancelRestartRequest(param::hstring const& requestRestartToken) const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateAdministratorStatics>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateAdministratorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateApprovalData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) Seeker() const;
        WINRT_IMPL_AUTO(void) Seeker(winrt::Windows::Foundation::IReference<bool> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) AllowDownloadOnMetered() const;
        WINRT_IMPL_AUTO(void) AllowDownloadOnMetered(winrt::Windows::Foundation::IReference<bool> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) ComplianceDeadlineInDays() const;
        WINRT_IMPL_AUTO(void) ComplianceDeadlineInDays(winrt::Windows::Foundation::IReference<int32_t> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) ComplianceGracePeriodInDays() const;
        WINRT_IMPL_AUTO(void) ComplianceGracePeriodInDays(winrt::Windows::Foundation::IReference<int32_t> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<bool>) OptOutOfAutoReboot() const;
        WINRT_IMPL_AUTO(void) OptOutOfAutoReboot(winrt::Windows::Foundation::IReference<bool> const& value) const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateApprovalData>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateApprovalData<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateAttentionRequiredInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReason) Reason() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) Timestamp() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredInfo>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateAttentionRequiredInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateAttentionRequiredReasonChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdate) Update() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReason) Reason() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateAttentionRequiredReasonChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateAttentionRequiredReasonChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateGetAdministratorResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateAdministrator) Administrator() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateAdministratorStatus) Status() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateGetAdministratorResult>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateGetAdministratorResult<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ProviderId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UpdateId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) MoreInfoUrl() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Category() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Operation() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateItem>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateItem<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateManager
    {
        WINRT_IMPL_AUTO(winrt::event_token) ScanningStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ScanningStateChanged_revoker = impl::event_revoker<winrt::Windows::Management::Update::IWindowsUpdateManager, &impl::abi_t<winrt::Windows::Management::Update::IWindowsUpdateManager>::remove_ScanningStateChanged>;
        [[nodiscard]] ScanningStateChanged_revoker ScanningStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ScanningStateChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) WorkingStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using WorkingStateChanged_revoker = impl::event_revoker<winrt::Windows::Management::Update::IWindowsUpdateManager, &impl::abi_t<winrt::Windows::Management::Update::IWindowsUpdateManager>::remove_WorkingStateChanged>;
        [[nodiscard]] WorkingStateChanged_revoker WorkingStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) WorkingStateChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ProgressChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateProgressChangedEventArgs> const& handler) const;
        using ProgressChanged_revoker = impl::event_revoker<winrt::Windows::Management::Update::IWindowsUpdateManager, &impl::abi_t<winrt::Windows::Management::Update::IWindowsUpdateManager>::remove_ProgressChanged>;
        [[nodiscard]] ProgressChanged_revoker ProgressChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateProgressChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ProgressChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AttentionRequiredReasonChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReasonChangedEventArgs> const& handler) const;
        using AttentionRequiredReasonChanged_revoker = impl::event_revoker<winrt::Windows::Management::Update::IWindowsUpdateManager, &impl::abi_t<winrt::Windows::Management::Update::IWindowsUpdateManager>::remove_AttentionRequiredReasonChanged>;
        [[nodiscard]] AttentionRequiredReasonChanged_revoker AttentionRequiredReasonChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateAttentionRequiredReasonChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AttentionRequiredReasonChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ActionCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateActionCompletedEventArgs> const& handler) const;
        using ActionCompleted_revoker = impl::event_revoker<winrt::Windows::Management::Update::IWindowsUpdateManager, &impl::abi_t<winrt::Windows::Management::Update::IWindowsUpdateManager>::remove_ActionCompleted>;
        [[nodiscard]] ActionCompleted_revoker ActionCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateActionCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ActionCompleted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ScanCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateScanCompletedEventArgs> const& handler) const;
        using ScanCompleted_revoker = impl::event_revoker<winrt::Windows::Management::Update::IWindowsUpdateManager, &impl::abi_t<winrt::Windows::Management::Update::IWindowsUpdateManager>::remove_ScanCompleted>;
        [[nodiscard]] ScanCompleted_revoker ScanCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Update::WindowsUpdateManager, winrt::Windows::Management::Update::WindowsUpdateScanCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ScanCompleted(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScanning() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsWorking() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) LastSuccessfulScanTimestamp() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::Update::WindowsUpdate>) GetApplicableUpdates() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::Update::WindowsUpdateItem>) GetMostRecentCompletedUpdates(int32_t count) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::Update::WindowsUpdateItem>>) GetMostRecentCompletedUpdatesAsync(int32_t count) const;
        WINRT_IMPL_AUTO(void) StartScan(bool userInitiated) const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateManager>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateManager<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateManagerFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateManager) CreateInstance(param::hstring const& clientId) const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateManagerFactory>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateManagerFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateProgressChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdate) Update() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateActionProgress) ActionProgress() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateProgressChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateProgressChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateRestartRequestOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        WINRT_IMPL_AUTO(void) Title(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        WINRT_IMPL_AUTO(void) Description(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) MoreInfoUrl() const;
        WINRT_IMPL_AUTO(void) MoreInfoUrl(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ComplianceDeadlineInDays() const;
        WINRT_IMPL_AUTO(void) ComplianceDeadlineInDays(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ComplianceGracePeriodInDays() const;
        WINRT_IMPL_AUTO(void) ComplianceGracePeriodInDays(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) OrganizationName() const;
        WINRT_IMPL_AUTO(void) OrganizationName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) OptOutOfAutoReboot() const;
        WINRT_IMPL_AUTO(void) OptOutOfAutoReboot(bool value) const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptions>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateRestartRequestOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateRestartRequestOptionsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Update::WindowsUpdateRestartRequestOptions) CreateInstance(param::hstring const& title, param::hstring const& description, winrt::Windows::Foundation::Uri const& moreInfoUrl, int32_t complianceDeadlineInDays, int32_t complianceGracePeriodInDays) const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateRestartRequestOptionsFactory>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateRestartRequestOptionsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Update_IWindowsUpdateScanCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ProviderId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Succeeded() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::Update::WindowsUpdate>) Updates() const;
    };
    template <> struct consume<winrt::Windows::Management::Update::IWindowsUpdateScanCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_Management_Update_IWindowsUpdateScanCompletedEventArgs<D>;
    };
}
#endif
