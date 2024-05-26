// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_EnterpriseData_0_H
#define WINRT_Windows_Security_EnterpriseData_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct Deferral;
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Networking
{
    struct HostName;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    enum class CreationCollisionOption : int32_t;
    struct IStorageFile;
    struct IStorageFolder;
    struct IStorageItem;
    enum class NameCollisionOption : int32_t;
    struct StorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
    struct IInputStream;
    struct IOutputStream;
    struct IRandomAccessStream;
}
WINRT_EXPORT namespace winrt::Windows::Security::EnterpriseData
{
    enum class DataProtectionStatus : int32_t
    {
        ProtectedToOtherIdentity = 0,
        Protected = 1,
        Revoked = 2,
        Unprotected = 3,
        LicenseExpired = 4,
        AccessSuspended = 5,
    };
    enum class EnforcementLevel : int32_t
    {
        NoProtection = 0,
        Silent = 1,
        Override = 2,
        Block = 3,
    };
    enum class FileProtectionStatus : int32_t
    {
        Undetermined = 0,
        Unknown = 0,
        Unprotected = 1,
        Revoked = 2,
        Protected = 3,
        ProtectedByOtherUser = 4,
        ProtectedToOtherEnterprise = 5,
        NotProtectable = 6,
        ProtectedToOtherIdentity = 7,
        LicenseExpired = 8,
        AccessSuspended = 9,
        FileInUse = 10,
    };
    enum class ProtectedImportExportStatus : int32_t
    {
        Ok = 0,
        Undetermined = 1,
        Unprotected = 2,
        Revoked = 3,
        NotRoamable = 4,
        ProtectedToOtherIdentity = 5,
        LicenseExpired = 6,
        AccessSuspended = 7,
    };
    enum class ProtectionPolicyAuditAction : int32_t
    {
        Decrypt = 0,
        CopyToLocation = 1,
        SendToRecipient = 2,
        Other = 3,
    };
    enum class ProtectionPolicyEvaluationResult : int32_t
    {
        Allowed = 0,
        Blocked = 1,
        ConsentRequired = 2,
    };
    enum class ProtectionPolicyRequestAccessBehavior : int32_t
    {
        Decrypt = 0,
        TreatOverridePolicyAsBlock = 1,
    };
    struct IBufferProtectUnprotectResult;
    struct IDataProtectionInfo;
    struct IDataProtectionManagerStatics;
    struct IFileProtectionInfo;
    struct IFileProtectionInfo2;
    struct IFileProtectionManagerStatics;
    struct IFileProtectionManagerStatics2;
    struct IFileProtectionManagerStatics3;
    struct IFileRevocationManagerStatics;
    struct IFileUnprotectOptions;
    struct IFileUnprotectOptionsFactory;
    struct IProtectedAccessResumedEventArgs;
    struct IProtectedAccessSuspendingEventArgs;
    struct IProtectedContainerExportResult;
    struct IProtectedContainerImportResult;
    struct IProtectedContentRevokedEventArgs;
    struct IProtectedFileCreateResult;
    struct IProtectionPolicyAuditInfo;
    struct IProtectionPolicyAuditInfoFactory;
    struct IProtectionPolicyManager;
    struct IProtectionPolicyManager2;
    struct IProtectionPolicyManagerStatics;
    struct IProtectionPolicyManagerStatics2;
    struct IProtectionPolicyManagerStatics3;
    struct IProtectionPolicyManagerStatics4;
    struct IThreadNetworkContext;
    struct BufferProtectUnprotectResult;
    struct DataProtectionInfo;
    struct DataProtectionManager;
    struct FileProtectionInfo;
    struct FileProtectionManager;
    struct FileRevocationManager;
    struct FileUnprotectOptions;
    struct ProtectedAccessResumedEventArgs;
    struct ProtectedAccessSuspendingEventArgs;
    struct ProtectedContainerExportResult;
    struct ProtectedContainerImportResult;
    struct ProtectedContentRevokedEventArgs;
    struct ProtectedFileCreateResult;
    struct ProtectionPolicyAuditInfo;
    struct ProtectionPolicyManager;
    struct ThreadNetworkContext;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IDataProtectionInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IDataProtectionManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileRevocationManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::IThreadNetworkContext>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::BufferProtectUnprotectResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::DataProtectionInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::DataProtectionManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::FileProtectionInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::FileProtectionManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::FileRevocationManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::FileUnprotectOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectedContainerExportResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectedFileCreateResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectionPolicyManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ThreadNetworkContext>{ using type = class_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::DataProtectionStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::EnforcementLevel>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::FileProtectionStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectedImportExportStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditAction>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::BufferProtectUnprotectResult> = L"Windows.Security.EnterpriseData.BufferProtectUnprotectResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::DataProtectionInfo> = L"Windows.Security.EnterpriseData.DataProtectionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::DataProtectionManager> = L"Windows.Security.EnterpriseData.DataProtectionManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::FileProtectionInfo> = L"Windows.Security.EnterpriseData.FileProtectionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::FileProtectionManager> = L"Windows.Security.EnterpriseData.FileProtectionManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::FileRevocationManager> = L"Windows.Security.EnterpriseData.FileRevocationManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::FileUnprotectOptions> = L"Windows.Security.EnterpriseData.FileUnprotectOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> = L"Windows.Security.EnterpriseData.ProtectedAccessResumedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> = L"Windows.Security.EnterpriseData.ProtectedAccessSuspendingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectedContainerExportResult> = L"Windows.Security.EnterpriseData.ProtectedContainerExportResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult> = L"Windows.Security.EnterpriseData.ProtectedContainerImportResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> = L"Windows.Security.EnterpriseData.ProtectedContentRevokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectedFileCreateResult> = L"Windows.Security.EnterpriseData.ProtectedFileCreateResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo> = L"Windows.Security.EnterpriseData.ProtectionPolicyAuditInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectionPolicyManager> = L"Windows.Security.EnterpriseData.ProtectionPolicyManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ThreadNetworkContext> = L"Windows.Security.EnterpriseData.ThreadNetworkContext";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::DataProtectionStatus> = L"Windows.Security.EnterpriseData.DataProtectionStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::EnforcementLevel> = L"Windows.Security.EnterpriseData.EnforcementLevel";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::FileProtectionStatus> = L"Windows.Security.EnterpriseData.FileProtectionStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectedImportExportStatus> = L"Windows.Security.EnterpriseData.ProtectedImportExportStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditAction> = L"Windows.Security.EnterpriseData.ProtectionPolicyAuditAction";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult> = L"Windows.Security.EnterpriseData.ProtectionPolicyEvaluationResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior> = L"Windows.Security.EnterpriseData.ProtectionPolicyRequestAccessBehavior";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult> = L"Windows.Security.EnterpriseData.IBufferProtectUnprotectResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IDataProtectionInfo> = L"Windows.Security.EnterpriseData.IDataProtectionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IDataProtectionManagerStatics> = L"Windows.Security.EnterpriseData.IDataProtectionManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo> = L"Windows.Security.EnterpriseData.IFileProtectionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo2> = L"Windows.Security.EnterpriseData.IFileProtectionInfo2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics> = L"Windows.Security.EnterpriseData.IFileProtectionManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics2> = L"Windows.Security.EnterpriseData.IFileProtectionManagerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics3> = L"Windows.Security.EnterpriseData.IFileProtectionManagerStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileRevocationManagerStatics> = L"Windows.Security.EnterpriseData.IFileRevocationManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions> = L"Windows.Security.EnterpriseData.IFileUnprotectOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory> = L"Windows.Security.EnterpriseData.IFileUnprotectOptionsFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs> = L"Windows.Security.EnterpriseData.IProtectedAccessResumedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs> = L"Windows.Security.EnterpriseData.IProtectedAccessSuspendingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult> = L"Windows.Security.EnterpriseData.IProtectedContainerExportResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult> = L"Windows.Security.EnterpriseData.IProtectedContainerImportResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs> = L"Windows.Security.EnterpriseData.IProtectedContentRevokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult> = L"Windows.Security.EnterpriseData.IProtectedFileCreateResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo> = L"Windows.Security.EnterpriseData.IProtectionPolicyAuditInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory> = L"Windows.Security.EnterpriseData.IProtectionPolicyAuditInfoFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager> = L"Windows.Security.EnterpriseData.IProtectionPolicyManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager2> = L"Windows.Security.EnterpriseData.IProtectionPolicyManager2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics> = L"Windows.Security.EnterpriseData.IProtectionPolicyManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2> = L"Windows.Security.EnterpriseData.IProtectionPolicyManagerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3> = L"Windows.Security.EnterpriseData.IProtectionPolicyManagerStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4> = L"Windows.Security.EnterpriseData.IProtectionPolicyManagerStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::Security::EnterpriseData::IThreadNetworkContext> = L"Windows.Security.EnterpriseData.IThreadNetworkContext";
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult>{ 0x47995EDC,0x6CEC,0x4E3A,{ 0xB2,0x51,0x9E,0x74,0x85,0xD7,0x9E,0x7A } }; // 47995EDC-6CEC-4E3A-B251-9E7485D79E7A
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IDataProtectionInfo>{ 0x8420B0C1,0x5E31,0x4405,{ 0x95,0x40,0x3F,0x94,0x3A,0xF0,0xCB,0x26 } }; // 8420B0C1-5E31-4405-9540-3F943AF0CB26
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IDataProtectionManagerStatics>{ 0xB6149B74,0x9144,0x4EE4,{ 0x8A,0x8A,0x30,0xB5,0xF3,0x61,0x43,0x0E } }; // B6149B74-9144-4EE4-8A8A-30B5F361430E
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo>{ 0x4EE96486,0x147E,0x4DD0,{ 0x8F,0xAF,0x52,0x53,0xED,0x91,0xAD,0x0C } }; // 4EE96486-147E-4DD0-8FAF-5253ED91AD0C
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo2>{ 0x82123A4C,0x557A,0x498D,{ 0x8E,0x94,0x94,0x4C,0xD5,0x83,0x64,0x32 } }; // 82123A4C-557A-498D-8E94-944CD5836432
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics>{ 0x5846FC9B,0xE613,0x426B,{ 0xBB,0x38,0x88,0xCB,0xA1,0xDC,0x9A,0xDB } }; // 5846FC9B-E613-426B-BB38-88CBA1DC9ADB
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>{ 0x83D2A745,0x0483,0x41AB,{ 0xB2,0xD5,0xBC,0x7F,0x23,0xD7,0x4E,0xBB } }; // 83D2A745-0483-41AB-B2D5-BC7F23D74EBB
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics3>{ 0x6918849A,0x624F,0x46D6,{ 0xB2,0x41,0xE9,0xCD,0x5F,0xDF,0x3E,0x3F } }; // 6918849A-624F-46D6-B241-E9CD5FDF3E3F
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileRevocationManagerStatics>{ 0x256BBC3D,0x1C5D,0x4260,{ 0x8C,0x75,0x91,0x44,0xCF,0xB7,0x8B,0xA9 } }; // 256BBC3D-1C5D-4260-8C75-9144CFB78BA9
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions>{ 0x7D1312F1,0x3B0D,0x4DD8,{ 0xA1,0xF8,0x1E,0xC5,0x38,0x22,0xE2,0xF3 } }; // 7D1312F1-3B0D-4DD8-A1F8-1EC53822E2F3
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory>{ 0x51AEB39C,0xDA8C,0x4C3F,{ 0x9B,0xFB,0xCB,0x73,0xA7,0xCC,0xE0,0xDD } }; // 51AEB39C-DA8C-4C3F-9BFB-CB73A7CCE0DD
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs>{ 0xAC4DCA59,0x5D80,0x4E95,{ 0x8C,0x5F,0x85,0x39,0x45,0x0E,0xEB,0xE0 } }; // AC4DCA59-5D80-4E95-8C5F-8539450EEBE0
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs>{ 0x75A193E0,0xA344,0x429F,{ 0xB9,0x75,0x04,0xFC,0x1F,0x88,0xC1,0x85 } }; // 75A193E0-A344-429F-B975-04FC1F88C185
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult>{ 0x3948EF95,0xF7FB,0x4B42,{ 0xAF,0xB0,0xDF,0x70,0xB4,0x15,0x43,0xC1 } }; // 3948EF95-F7FB-4B42-AFB0-DF70B41543C1
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult>{ 0xCDB780D1,0xE7BB,0x4D1A,{ 0x93,0x39,0x34,0xDC,0x41,0x14,0x9F,0x9B } }; // CDB780D1-E7BB-4D1A-9339-34DC41149F9B
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs>{ 0x63686821,0x58B9,0x47EE,{ 0x93,0xD9,0xF0,0xF7,0x41,0xCF,0x43,0xF0 } }; // 63686821-58B9-47EE-93D9-F0F741CF43F0
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult>{ 0x28E3ED6A,0xE9E7,0x4A03,{ 0x9F,0x53,0xBD,0xB1,0x61,0x72,0x69,0x9B } }; // 28E3ED6A-E9E7-4A03-9F53-BDB16172699B
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo>{ 0x425AB7E4,0xFEB7,0x44FC,{ 0xB3,0xBB,0xC3,0xC4,0xD7,0xEC,0xBE,0xBB } }; // 425AB7E4-FEB7-44FC-B3BB-C3C4D7ECBEBB
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory>{ 0x7ED4180B,0x92E8,0x42D5,{ 0x83,0xD4,0x25,0x44,0x0B,0x42,0x35,0x49 } }; // 7ED4180B-92E8-42D5-83D4-25440B423549
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager>{ 0xD5703E18,0xA08D,0x47E6,{ 0xA2,0x40,0x99,0x34,0xD7,0x16,0x5E,0xB5 } }; // D5703E18-A08D-47E6-A240-9934D7165EB5
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager2>{ 0xABF7527A,0x8435,0x417F,{ 0x99,0xB6,0x51,0xBE,0xAF,0x36,0x58,0x88 } }; // ABF7527A-8435-417F-99B6-51BEAF365888
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>{ 0xC0BFFC66,0x8C3D,0x4D56,{ 0x88,0x04,0xC6,0x8F,0x0A,0xD3,0x2E,0xC5 } }; // C0BFFC66-8C3D-4D56-8804-C68F0AD32EC5
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>{ 0xB68F9A8C,0x39E0,0x4649,{ 0xB2,0xE4,0x07,0x0A,0xB8,0xA5,0x79,0xB3 } }; // B68F9A8C-39E0-4649-B2E4-070AB8A579B3
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>{ 0x48FF9E8C,0x6A6F,0x4D9F,{ 0xBC,0xED,0x18,0xAB,0x53,0x7A,0xA0,0x15 } }; // 48FF9E8C-6A6F-4D9F-BCED-18AB537AA015
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>{ 0x20B794DB,0xCCBD,0x490F,{ 0x8C,0x83,0x49,0xCC,0xB7,0x7A,0xEA,0x6C } }; // 20B794DB-CCBD-490F-8C83-49CCB77AEA6C
    template <> inline constexpr guid guid_v<winrt::Windows::Security::EnterpriseData::IThreadNetworkContext>{ 0xFA4EA8E9,0xEF13,0x405A,{ 0xB1,0x2C,0xD7,0x34,0x8C,0x6F,0x41,0xFC } }; // FA4EA8E9-EF13-405A-B12C-D7348C6F41FC
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::BufferProtectUnprotectResult>{ using type = winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::DataProtectionInfo>{ using type = winrt::Windows::Security::EnterpriseData::IDataProtectionInfo; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::FileProtectionInfo>{ using type = winrt::Windows::Security::EnterpriseData::IFileProtectionInfo; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::FileUnprotectOptions>{ using type = winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs>{ using type = winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs>{ using type = winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectedContainerExportResult>{ using type = winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult>{ using type = winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs>{ using type = winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectedFileCreateResult>{ using type = winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo>{ using type = winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ProtectionPolicyManager>{ using type = winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager; };
    template <> struct default_interface<winrt::Windows::Security::EnterpriseData::ThreadNetworkContext>{ using type = winrt::Windows::Security::EnterpriseData::IThreadNetworkContext; };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Buffer(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProtectionInfo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IDataProtectionInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Identity(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IDataProtectionManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ProtectAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall UnprotectAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ProtectStreamAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall UnprotectStreamAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetProtectionInfoAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetStreamProtectionInfoAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsRoamable(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Identity(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsProtectWhileOpenSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ProtectAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CopyProtectionAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetProtectionInfoAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SaveFileAsContainerAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall LoadFileFromContainerAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall LoadFileFromContainerWithTargetAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateProtectedAndOpenAsync(void*, void*, void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsContainerAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall LoadFileFromContainerWithTargetAndNameCollisionOptionAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SaveFileAsContainerWithSharingAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall UnprotectAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UnprotectWithOptionsAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileRevocationManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ProtectAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CopyProtectionAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall Revoke(void*) noexcept = 0;
            virtual int32_t __stdcall GetStatusAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Audit(bool) noexcept = 0;
            virtual int32_t __stdcall get_Audit(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(bool, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Identities(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Identities(void**) noexcept = 0;
            virtual int32_t __stdcall get_Deadline(int64_t*) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_File(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_File(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Identities(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_File(void**) noexcept = 0;
            virtual int32_t __stdcall get_Stream(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProtectionInfo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Action(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_Action(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_DataDescription(void*) noexcept = 0;
            virtual int32_t __stdcall get_DataDescription(void**) noexcept = 0;
            virtual int32_t __stdcall put_SourceDescription(void*) noexcept = 0;
            virtual int32_t __stdcall get_SourceDescription(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetDescription(void*) noexcept = 0;
            virtual int32_t __stdcall get_TargetDescription(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(int32_t, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithActionAndDataDescription(int32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Identity(void*) noexcept = 0;
            virtual int32_t __stdcall get_Identity(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ShowEnterpriseIndicator(bool) noexcept = 0;
            virtual int32_t __stdcall get_ShowEnterpriseIndicator(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsIdentityManaged(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall TryApplyProcessUIPolicy(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall ClearProcessUIPolicy() noexcept = 0;
            virtual int32_t __stdcall CreateCurrentThreadNetworkContext(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetPrimaryManagedIdentityForNetworkEndpointAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RevokeContent(void*) noexcept = 0;
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
            virtual int32_t __stdcall add_ProtectedAccessSuspending(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProtectedAccessSuspending(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ProtectedAccessResumed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProtectedAccessResumed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ProtectedContentRevoked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProtectedContentRevoked(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall CheckAccess(void*, void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall RequestAccessAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall HasContentBeenRevokedSince(void*, int64_t, bool*) noexcept = 0;
            virtual int32_t __stdcall CheckAccessForApp(void*, void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall RequestAccessForAppAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetEnforcementLevel(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall IsUserDecryptionAllowed(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall IsProtectionUnderLockRequired(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall add_PolicyChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PolicyChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_IsProtectionEnabled(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestAccessWithAuditingInfoAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessWithMessageAsync(void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessForAppWithAuditingInfoAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessForAppWithMessageAsync(void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall LogAuditEvent(void*, void*, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsRoamableProtectionEnabled(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall RequestAccessWithBehaviorAsync(void*, void*, void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessForAppWithBehaviorAsync(void*, void*, void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessToFilesForAppAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessToFilesForAppWithMessageAndBehaviorAsync(void*, void*, void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessToFilesForProcessAsync(void*, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessToFilesForProcessWithMessageAndBehaviorAsync(void*, uint32_t, void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall IsFileProtectionRequiredAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall IsFileProtectionRequiredForNewFileAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_PrimaryManagedIdentity(void**) noexcept = 0;
            virtual int32_t __stdcall GetPrimaryManagedIdentityForIdentity(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Security::EnterpriseData::IThreadNetworkContext>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IBufferProtectUnprotectResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Buffer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::DataProtectionInfo) ProtectionInfo() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IBufferProtectUnprotectResult>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IBufferProtectUnprotectResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IDataProtectionInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::DataProtectionStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Identity() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IDataProtectionInfo>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IDataProtectionInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::BufferProtectUnprotectResult>) ProtectAsync(winrt::Windows::Storage::Streams::IBuffer const& data, param::hstring const& identity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::BufferProtectUnprotectResult>) UnprotectAsync(winrt::Windows::Storage::Streams::IBuffer const& data) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::DataProtectionInfo>) ProtectStreamAsync(winrt::Windows::Storage::Streams::IInputStream const& unprotectedStream, param::hstring const& identity, winrt::Windows::Storage::Streams::IOutputStream const& protectedStream) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::DataProtectionInfo>) UnprotectStreamAsync(winrt::Windows::Storage::Streams::IInputStream const& protectedStream, winrt::Windows::Storage::Streams::IOutputStream const& unprotectedStream) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::DataProtectionInfo>) GetProtectionInfoAsync(winrt::Windows::Storage::Streams::IBuffer const& protectedData) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::DataProtectionInfo>) GetStreamProtectionInfoAsync(winrt::Windows::Storage::Streams::IInputStream const& protectedStream) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IDataProtectionManagerStatics>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IDataProtectionManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileProtectionInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::FileProtectionStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsRoamable() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Identity() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileProtectionInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileProtectionInfo2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsProtectWhileOpenSupported() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileProtectionInfo2>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileProtectionInfo2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::FileProtectionInfo>) ProtectAsync(winrt::Windows::Storage::IStorageItem const& target, param::hstring const& identity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) CopyProtectionAsync(winrt::Windows::Storage::IStorageItem const& source, winrt::Windows::Storage::IStorageItem const& target) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::FileProtectionInfo>) GetProtectionInfoAsync(winrt::Windows::Storage::IStorageItem const& source) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectedContainerExportResult>) SaveFileAsContainerAsync(winrt::Windows::Storage::IStorageFile const& protectedFile) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult>) LoadFileFromContainerAsync(winrt::Windows::Storage::IStorageFile const& containerFile) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult>) LoadFileFromContainerAsync(winrt::Windows::Storage::IStorageFile const& containerFile, winrt::Windows::Storage::IStorageItem const& target) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectedFileCreateResult>) CreateProtectedAndOpenAsync(winrt::Windows::Storage::IStorageFolder const& parentFolder, param::hstring const& desiredName, param::hstring const& identity, winrt::Windows::Storage::CreationCollisionOption const& collisionOption) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) IsContainerAsync(winrt::Windows::Storage::IStorageFile const& file) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectedContainerImportResult>) LoadFileFromContainerAsync(winrt::Windows::Storage::IStorageFile const& containerFile, winrt::Windows::Storage::IStorageItem const& target, winrt::Windows::Storage::NameCollisionOption const& collisionOption) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectedContainerExportResult>) SaveFileAsContainerAsync(winrt::Windows::Storage::IStorageFile const& protectedFile, param::async_iterable<hstring> const& sharedWithIdentities) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics2>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::FileProtectionInfo>) UnprotectAsync(winrt::Windows::Storage::IStorageItem const& target) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::FileProtectionInfo>) UnprotectAsync(winrt::Windows::Storage::IStorageItem const& target, winrt::Windows::Security::EnterpriseData::FileUnprotectOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileProtectionManagerStatics3>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileProtectionManagerStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileRevocationManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::FileProtectionStatus>) ProtectAsync(winrt::Windows::Storage::IStorageItem const& storageItem, param::hstring const& enterpriseIdentity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) CopyProtectionAsync(winrt::Windows::Storage::IStorageItem const& sourceStorageItem, winrt::Windows::Storage::IStorageItem const& targetStorageItem) const;
        WINRT_IMPL_AUTO(void) Revoke(param::hstring const& enterpriseIdentity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::FileProtectionStatus>) GetStatusAsync(winrt::Windows::Storage::IStorageItem const& storageItem) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileRevocationManagerStatics>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileRevocationManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileUnprotectOptions
    {
        WINRT_IMPL_AUTO(void) Audit(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Audit() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptions>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileUnprotectOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IFileUnprotectOptionsFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::FileUnprotectOptions) Create(bool audit) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IFileUnprotectOptionsFactory>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IFileUnprotectOptionsFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectedAccessResumedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Identities() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectedAccessResumedEventArgs>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectedAccessResumedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectedAccessSuspendingEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Identities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Deadline() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectedAccessSuspendingEventArgs>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectedAccessSuspendingEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectedContainerExportResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectedImportExportStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) File() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectedContainerExportResult>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectedContainerExportResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectedContainerImportResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectedImportExportStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) File() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectedContainerImportResult>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectedContainerImportResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectedContentRevokedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Identities() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectedContentRevokedEventArgs>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectedContentRevokedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectedFileCreateResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) File() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStream) Stream() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::FileProtectionInfo) ProtectionInfo() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectedFileCreateResult>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectedFileCreateResult<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo
    {
        WINRT_IMPL_AUTO(void) Action(winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditAction) Action() const;
        WINRT_IMPL_AUTO(void) DataDescription(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DataDescription() const;
        WINRT_IMPL_AUTO(void) SourceDescription(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SourceDescription() const;
        WINRT_IMPL_AUTO(void) TargetDescription(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TargetDescription() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfo>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfoFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo) Create(winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& action, param::hstring const& dataDescription, param::hstring const& sourceDescription, param::hstring const& targetDescription) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo) CreateWithActionAndDataDescription(winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditAction const& action, param::hstring const& dataDescription) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyAuditInfoFactory>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyAuditInfoFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyManager
    {
        WINRT_IMPL_AUTO(void) Identity(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Identity() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyManager<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyManager2
    {
        WINRT_IMPL_AUTO(void) ShowEnterpriseIndicator(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowEnterpriseIndicator() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManager2>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyManager2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics
    {
        WINRT_IMPL_AUTO(bool) IsIdentityManaged(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(bool) TryApplyProcessUIPolicy(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(void) ClearProcessUIPolicy() const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ThreadNetworkContext) CreateCurrentThreadNetworkContext(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetPrimaryManagedIdentityForNetworkEndpointAsync(winrt::Windows::Networking::HostName const& endpointHost) const;
        WINRT_IMPL_AUTO(void) RevokeContent(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectionPolicyManager) GetForCurrentView() const;
        WINRT_IMPL_AUTO(winrt::event_token) ProtectedAccessSuspending(winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const& handler) const;
        using ProtectedAccessSuspending_revoker = impl::event_revoker<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics, &impl::abi_t<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>::remove_ProtectedAccessSuspending>;
        [[nodiscard]] ProtectedAccessSuspending_revoker ProtectedAccessSuspending(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::EnterpriseData::ProtectedAccessSuspendingEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ProtectedAccessSuspending(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ProtectedAccessResumed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const& handler) const;
        using ProtectedAccessResumed_revoker = impl::event_revoker<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics, &impl::abi_t<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>::remove_ProtectedAccessResumed>;
        [[nodiscard]] ProtectedAccessResumed_revoker ProtectedAccessResumed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::EnterpriseData::ProtectedAccessResumedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ProtectedAccessResumed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ProtectedContentRevoked(winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const& handler) const;
        using ProtectedContentRevoked_revoker = impl::event_revoker<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics, &impl::abi_t<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>::remove_ProtectedContentRevoked>;
        [[nodiscard]] ProtectedContentRevoked_revoker ProtectedContentRevoked(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::EnterpriseData::ProtectedContentRevokedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ProtectedContentRevoked(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult) CheckAccess(param::hstring const& sourceIdentity, param::hstring const& targetIdentity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2
    {
        WINRT_IMPL_AUTO(bool) HasContentBeenRevokedSince(param::hstring const& identity, winrt::Windows::Foundation::DateTime const& since) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult) CheckAccessForApp(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Security::EnterpriseData::EnforcementLevel) GetEnforcementLevel(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(bool) IsUserDecryptionAllowed(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(bool) IsProtectionUnderLockRequired(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(winrt::event_token) PolicyChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        using PolicyChanged_revoker = impl::event_revoker<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2, &impl::abi_t<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>::remove_PolicyChanged>;
        [[nodiscard]] PolicyChanged_revoker PolicyChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) PolicyChanged(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsProtectionEnabled() const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics2>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp) const;
        WINRT_IMPL_AUTO(void) LogAuditEvent(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics3>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4
    {
        WINRT_IMPL_AUTO(bool) IsRoamableProtectionEnabled(param::hstring const& identity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessAsync(param::hstring const& sourceIdentity, param::hstring const& targetIdentity, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, winrt::Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessForAppAsync(param::hstring const& sourceIdentity, param::hstring const& appPackageFamilyName, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, winrt::Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessToFilesForAppAsync(param::async_iterable<winrt::Windows::Storage::IStorageItem> const& sourceItemList, param::hstring const& appPackageFamilyName, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessToFilesForAppAsync(param::async_iterable<winrt::Windows::Storage::IStorageItem> const& sourceItemList, param::hstring const& appPackageFamilyName, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, winrt::Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessToFilesForProcessAsync(param::async_iterable<winrt::Windows::Storage::IStorageItem> const& sourceItemList, uint32_t processId, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::EnterpriseData::ProtectionPolicyEvaluationResult>) RequestAccessToFilesForProcessAsync(param::async_iterable<winrt::Windows::Storage::IStorageItem> const& sourceItemList, uint32_t processId, winrt::Windows::Security::EnterpriseData::ProtectionPolicyAuditInfo const& auditInfo, param::hstring const& messageFromApp, winrt::Windows::Security::EnterpriseData::ProtectionPolicyRequestAccessBehavior const& behavior) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) IsFileProtectionRequiredAsync(winrt::Windows::Storage::IStorageItem const& target, param::hstring const& identity) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) IsFileProtectionRequiredForNewFileAsync(winrt::Windows::Storage::IStorageFolder const& parentFolder, param::hstring const& identity, param::hstring const& desiredName) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PrimaryManagedIdentity() const;
        WINRT_IMPL_AUTO(hstring) GetPrimaryManagedIdentityForIdentity(param::hstring const& identity) const;
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IProtectionPolicyManagerStatics4>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IProtectionPolicyManagerStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_Security_EnterpriseData_IThreadNetworkContext
    {
    };
    template <> struct consume<winrt::Windows::Security::EnterpriseData::IThreadNetworkContext>
    {
        template <typename D> using type = consume_Windows_Security_EnterpriseData_IThreadNetworkContext<D>;
    };
}
#endif
