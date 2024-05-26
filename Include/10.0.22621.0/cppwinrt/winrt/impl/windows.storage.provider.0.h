// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Provider_0_H
#define WINRT_Windows_Storage_Provider_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct IStorageFile;
    struct IStorageFolder;
    struct IStorageItem;
    struct StorageFile;
    struct StorageFolder;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct Color;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Provider
{
    enum class CachedFileOptions : uint32_t
    {
        None = 0,
        RequireUpdateOnAccess = 0x1,
        UseCachedFileWhenOffline = 0x2,
        DenyAccessWhenOffline = 0x4,
    };
    enum class CachedFileTarget : int32_t
    {
        Local = 0,
        Remote = 1,
    };
    enum class FileUpdateStatus : int32_t
    {
        Incomplete = 0,
        Complete = 1,
        UserInputNeeded = 2,
        CurrentlyUnavailable = 3,
        Failed = 4,
        CompleteAndRenamed = 5,
    };
    enum class ReadActivationMode : int32_t
    {
        NotNeeded = 0,
        BeforeAccess = 1,
    };
    enum class StorageProviderHardlinkPolicy : uint32_t
    {
        None = 0,
        Allowed = 0x1,
    };
    enum class StorageProviderHydrationPolicy : int32_t
    {
        Partial = 0,
        Progressive = 1,
        Full = 2,
        AlwaysFull = 3,
    };
    enum class StorageProviderHydrationPolicyModifier : uint32_t
    {
        None = 0,
        ValidationRequired = 0x1,
        StreamingAllowed = 0x2,
        AutoDehydrationAllowed = 0x4,
        AllowFullRestartHydration = 0x8,
    };
    enum class StorageProviderInSyncPolicy : uint32_t
    {
        Default = 0,
        FileCreationTime = 0x1,
        FileReadOnlyAttribute = 0x2,
        FileHiddenAttribute = 0x4,
        FileSystemAttribute = 0x8,
        DirectoryCreationTime = 0x10,
        DirectoryReadOnlyAttribute = 0x20,
        DirectoryHiddenAttribute = 0x40,
        DirectorySystemAttribute = 0x80,
        FileLastWriteTime = 0x100,
        DirectoryLastWriteTime = 0x200,
        PreserveInsyncForSyncEngine = 0x80000000,
    };
    enum class StorageProviderKnownFolderSyncStatus : int32_t
    {
        Available = 0,
        Enrolling = 1,
        Enrolled = 2,
    };
    enum class StorageProviderPopulationPolicy : int32_t
    {
        Full = 1,
        AlwaysFull = 2,
    };
    enum class StorageProviderProtectionMode : int32_t
    {
        Unknown = 0,
        Personal = 1,
    };
    enum class StorageProviderState : int32_t
    {
        InSync = 0,
        Syncing = 1,
        Paused = 2,
        Error = 3,
        Warning = 4,
        Offline = 5,
    };
    enum class StorageProviderUICommandState : int32_t
    {
        Enabled = 0,
        Disabled = 1,
        Hidden = 2,
    };
    enum class StorageProviderUriSourceStatus : int32_t
    {
        Success = 0,
        NoSyncRoot = 1,
        FileNotFound = 2,
    };
    enum class UIStatus : int32_t
    {
        Unavailable = 0,
        Hidden = 1,
        Visible = 2,
        Complete = 3,
    };
    enum class WriteActivationMode : int32_t
    {
        ReadOnly = 0,
        NotNeeded = 1,
        AfterWrite = 2,
    };
    struct ICachedFileUpdaterStatics;
    struct ICachedFileUpdaterUI;
    struct ICachedFileUpdaterUI2;
    struct IFileUpdateRequest;
    struct IFileUpdateRequest2;
    struct IFileUpdateRequestDeferral;
    struct IFileUpdateRequestedEventArgs;
    struct IStorageProviderFileTypeInfo;
    struct IStorageProviderFileTypeInfoFactory;
    struct IStorageProviderGetContentInfoForPathResult;
    struct IStorageProviderGetPathForContentUriResult;
    struct IStorageProviderItemPropertiesStatics;
    struct IStorageProviderItemProperty;
    struct IStorageProviderItemPropertyDefinition;
    struct IStorageProviderItemPropertySource;
    struct IStorageProviderKnownFolderEntry;
    struct IStorageProviderKnownFolderSyncInfo;
    struct IStorageProviderKnownFolderSyncInfoSource;
    struct IStorageProviderKnownFolderSyncInfoSourceFactory;
    struct IStorageProviderKnownFolderSyncRequestArgs;
    struct IStorageProviderMoreInfoUI;
    struct IStorageProviderPropertyCapabilities;
    struct IStorageProviderQuotaUI;
    struct IStorageProviderStatusUI;
    struct IStorageProviderStatusUISource;
    struct IStorageProviderStatusUISourceFactory;
    struct IStorageProviderSyncRootInfo;
    struct IStorageProviderSyncRootInfo2;
    struct IStorageProviderSyncRootInfo3;
    struct IStorageProviderSyncRootManagerStatics;
    struct IStorageProviderSyncRootManagerStatics2;
    struct IStorageProviderUICommand;
    struct IStorageProviderUriSource;
    struct CachedFileUpdater;
    struct CachedFileUpdaterUI;
    struct FileUpdateRequest;
    struct FileUpdateRequestDeferral;
    struct FileUpdateRequestedEventArgs;
    struct StorageProviderFileTypeInfo;
    struct StorageProviderGetContentInfoForPathResult;
    struct StorageProviderGetPathForContentUriResult;
    struct StorageProviderItemProperties;
    struct StorageProviderItemProperty;
    struct StorageProviderItemPropertyDefinition;
    struct StorageProviderKnownFolderEntry;
    struct StorageProviderKnownFolderSyncInfo;
    struct StorageProviderKnownFolderSyncRequestArgs;
    struct StorageProviderMoreInfoUI;
    struct StorageProviderQuotaUI;
    struct StorageProviderStatusUI;
    struct StorageProviderSyncRootInfo;
    struct StorageProviderSyncRootManager;
    struct StorageProviderKnownFolderSyncRequestedHandler;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IFileUpdateRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IFileUpdateRequest2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderItemProperty>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderQuotaUI>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderStatusUI>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderUICommand>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::IStorageProviderUriSource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Provider::CachedFileUpdater>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::CachedFileUpdaterUI>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::FileUpdateRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderItemProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderItemProperty>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderQuotaUI>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderStatusUI>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderSyncRootManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Provider::CachedFileOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::CachedFileTarget>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::FileUpdateStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::ReadActivationMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderProtectionMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderUICommandState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::UIStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::WriteActivationMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::CachedFileUpdater> = L"Windows.Storage.Provider.CachedFileUpdater";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::CachedFileUpdaterUI> = L"Windows.Storage.Provider.CachedFileUpdaterUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::FileUpdateRequest> = L"Windows.Storage.Provider.FileUpdateRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral> = L"Windows.Storage.Provider.FileUpdateRequestDeferral";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> = L"Windows.Storage.Provider.FileUpdateRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo> = L"Windows.Storage.Provider.StorageProviderFileTypeInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult> = L"Windows.Storage.Provider.StorageProviderGetContentInfoForPathResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult> = L"Windows.Storage.Provider.StorageProviderGetPathForContentUriResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderItemProperties> = L"Windows.Storage.Provider.StorageProviderItemProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderItemProperty> = L"Windows.Storage.Provider.StorageProviderItemProperty";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition> = L"Windows.Storage.Provider.StorageProviderItemPropertyDefinition";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry> = L"Windows.Storage.Provider.StorageProviderKnownFolderEntry";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo> = L"Windows.Storage.Provider.StorageProviderKnownFolderSyncInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestArgs> = L"Windows.Storage.Provider.StorageProviderKnownFolderSyncRequestArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI> = L"Windows.Storage.Provider.StorageProviderMoreInfoUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderQuotaUI> = L"Windows.Storage.Provider.StorageProviderQuotaUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderStatusUI> = L"Windows.Storage.Provider.StorageProviderStatusUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo> = L"Windows.Storage.Provider.StorageProviderSyncRootInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderSyncRootManager> = L"Windows.Storage.Provider.StorageProviderSyncRootManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::CachedFileOptions> = L"Windows.Storage.Provider.CachedFileOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::CachedFileTarget> = L"Windows.Storage.Provider.CachedFileTarget";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::FileUpdateStatus> = L"Windows.Storage.Provider.FileUpdateStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::ReadActivationMode> = L"Windows.Storage.Provider.ReadActivationMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy> = L"Windows.Storage.Provider.StorageProviderHardlinkPolicy";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy> = L"Windows.Storage.Provider.StorageProviderHydrationPolicy";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier> = L"Windows.Storage.Provider.StorageProviderHydrationPolicyModifier";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy> = L"Windows.Storage.Provider.StorageProviderInSyncPolicy";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus> = L"Windows.Storage.Provider.StorageProviderKnownFolderSyncStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy> = L"Windows.Storage.Provider.StorageProviderPopulationPolicy";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderProtectionMode> = L"Windows.Storage.Provider.StorageProviderProtectionMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderState> = L"Windows.Storage.Provider.StorageProviderState";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderUICommandState> = L"Windows.Storage.Provider.StorageProviderUICommandState";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus> = L"Windows.Storage.Provider.StorageProviderUriSourceStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::UIStatus> = L"Windows.Storage.Provider.UIStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::WriteActivationMode> = L"Windows.Storage.Provider.WriteActivationMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics> = L"Windows.Storage.Provider.ICachedFileUpdaterStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI> = L"Windows.Storage.Provider.ICachedFileUpdaterUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2> = L"Windows.Storage.Provider.ICachedFileUpdaterUI2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IFileUpdateRequest> = L"Windows.Storage.Provider.IFileUpdateRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IFileUpdateRequest2> = L"Windows.Storage.Provider.IFileUpdateRequest2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral> = L"Windows.Storage.Provider.IFileUpdateRequestDeferral";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs> = L"Windows.Storage.Provider.IFileUpdateRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo> = L"Windows.Storage.Provider.IStorageProviderFileTypeInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory> = L"Windows.Storage.Provider.IStorageProviderFileTypeInfoFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult> = L"Windows.Storage.Provider.IStorageProviderGetContentInfoForPathResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult> = L"Windows.Storage.Provider.IStorageProviderGetPathForContentUriResult";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics> = L"Windows.Storage.Provider.IStorageProviderItemPropertiesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderItemProperty> = L"Windows.Storage.Provider.IStorageProviderItemProperty";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition> = L"Windows.Storage.Provider.IStorageProviderItemPropertyDefinition";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource> = L"Windows.Storage.Provider.IStorageProviderItemPropertySource";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry> = L"Windows.Storage.Provider.IStorageProviderKnownFolderEntry";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo> = L"Windows.Storage.Provider.IStorageProviderKnownFolderSyncInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource> = L"Windows.Storage.Provider.IStorageProviderKnownFolderSyncInfoSource";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory> = L"Windows.Storage.Provider.IStorageProviderKnownFolderSyncInfoSourceFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs> = L"Windows.Storage.Provider.IStorageProviderKnownFolderSyncRequestArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI> = L"Windows.Storage.Provider.IStorageProviderMoreInfoUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities> = L"Windows.Storage.Provider.IStorageProviderPropertyCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderQuotaUI> = L"Windows.Storage.Provider.IStorageProviderQuotaUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderStatusUI> = L"Windows.Storage.Provider.IStorageProviderStatusUI";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource> = L"Windows.Storage.Provider.IStorageProviderStatusUISource";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory> = L"Windows.Storage.Provider.IStorageProviderStatusUISourceFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo> = L"Windows.Storage.Provider.IStorageProviderSyncRootInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2> = L"Windows.Storage.Provider.IStorageProviderSyncRootInfo2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3> = L"Windows.Storage.Provider.IStorageProviderSyncRootInfo3";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics> = L"Windows.Storage.Provider.IStorageProviderSyncRootManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2> = L"Windows.Storage.Provider.IStorageProviderSyncRootManagerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderUICommand> = L"Windows.Storage.Provider.IStorageProviderUICommand";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::IStorageProviderUriSource> = L"Windows.Storage.Provider.IStorageProviderUriSource";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler> = L"Windows.Storage.Provider.StorageProviderKnownFolderSyncRequestedHandler";
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics>{ 0x9FC90920,0x7BCF,0x4888,{ 0xA8,0x1E,0x10,0x2D,0x70,0x34,0xD7,0xCE } }; // 9FC90920-7BCF-4888-A81E-102D7034D7CE
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI>{ 0x9E6F41E6,0xBAF2,0x4A97,{ 0xB6,0x00,0x93,0x33,0xF5,0xDF,0x80,0xFD } }; // 9E6F41E6-BAF2-4A97-B600-9333F5DF80FD
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2>{ 0x8856A21C,0x8699,0x4340,{ 0x9F,0x49,0xF7,0xCA,0xD7,0xFE,0x89,0x91 } }; // 8856A21C-8699-4340-9F49-F7CAD7FE8991
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IFileUpdateRequest>{ 0x40C82536,0xC1FE,0x4D93,{ 0xA7,0x92,0x1E,0x73,0x6B,0xC7,0x08,0x37 } }; // 40C82536-C1FE-4D93-A792-1E736BC70837
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IFileUpdateRequest2>{ 0x82484648,0xBDBE,0x447B,{ 0xA2,0xEE,0x7A,0xFE,0x6A,0x03,0x2A,0x94 } }; // 82484648-BDBE-447B-A2EE-7AFE6A032A94
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral>{ 0xFFCEDB2B,0x8ADE,0x44A5,{ 0xBB,0x00,0x16,0x4C,0x4E,0x72,0xF1,0x3A } }; // FFCEDB2B-8ADE-44A5-BB00-164C4E72F13A
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs>{ 0x7B0A9342,0x3905,0x438D,{ 0xAA,0xEF,0x78,0xAE,0x26,0x5F,0x8D,0xD2 } }; // 7B0A9342-3905-438D-AAEF-78AE265F8DD2
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo>{ 0x1955B9C1,0x0184,0x5A88,{ 0x87,0xDF,0x45,0x44,0xF4,0x64,0x36,0x5D } }; // 1955B9C1-0184-5A88-87DF-4544F464365D
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory>{ 0x3FA12C6F,0xCCE6,0x5D5D,{ 0x80,0xB1,0x38,0x9E,0x7C,0xF9,0x2D,0xBF } }; // 3FA12C6F-CCE6-5D5D-80B1-389E7CF92DBF
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>{ 0x2564711D,0xAA89,0x4D12,{ 0x82,0xE3,0xF7,0x2A,0x92,0xE3,0x39,0x66 } }; // 2564711D-AA89-4D12-82E3-F72A92E33966
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>{ 0x63711A9D,0x4118,0x45A6,{ 0xAC,0xB6,0x22,0xC4,0x9D,0x01,0x9F,0x40 } }; // 63711A9D-4118-45A6-ACB6-22C49D019F40
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>{ 0x2D2C1C97,0x2704,0x4729,{ 0x8F,0xA9,0x7E,0x6B,0x8E,0x15,0x8C,0x2F } }; // 2D2C1C97-2704-4729-8FA9-7E6B8E158C2F
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderItemProperty>{ 0x476CB558,0x730B,0x4188,{ 0xB7,0xB5,0x63,0xB7,0x16,0xED,0x47,0x6D } }; // 476CB558-730B-4188-B7B5-63B716ED476D
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>{ 0xC5B383BB,0xFF1F,0x4298,{ 0x83,0x1E,0xFF,0x1C,0x08,0x08,0x96,0x90 } }; // C5B383BB-FF1F-4298-831E-FF1C08089690
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource>{ 0x8F6F9C3E,0xF632,0x4A9B,{ 0x8D,0x99,0xD2,0xD7,0xA1,0x1D,0xF5,0x6A } }; // 8F6F9C3E-F632-4A9B-8D99-D2D7A11DF56A
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry>{ 0xEFFA7DB0,0x1D44,0x596B,{ 0x84,0x64,0x92,0x88,0x00,0xC5,0xE2,0xD8 } }; // EFFA7DB0-1D44-596B-8464-928800C5E2D8
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo>{ 0x98B017CE,0xFFC1,0x5B11,{ 0xAE,0x77,0xCC,0x17,0xAF,0xEC,0x10,0x49 } }; // 98B017CE-FFC1-5B11-AE77-CC17AFEC1049
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource>{ 0x51359342,0xF7C0,0x53D0,{ 0xBB,0xB6,0x1C,0xDC,0x09,0x8E,0xBD,0xA9 } }; // 51359342-F7C0-53D0-BBB6-1CDC098EBDA9
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory>{ 0xAAEE03A7,0xA7F6,0x50BE,{ 0xA9,0xB0,0x8E,0x82,0xD0,0xC8,0x10,0x82 } }; // AAEE03A7-A7F6-50BE-A9B0-8E82D0C81082
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs>{ 0xEDA6D569,0xB4E8,0x542F,{ 0xAB,0x8D,0xF3,0x61,0x3F,0x25,0x0A,0x4A } }; // EDA6D569-B4E8-542F-AB8D-F3613F250A4A
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI>{ 0xEF38E591,0xA7CB,0x5E7D,{ 0x9B,0x5E,0x22,0x74,0x98,0x42,0x69,0x7C } }; // EF38E591-A7CB-5E7D-9B5E-22749842697C
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities>{ 0x658D2F0E,0x63B7,0x4567,{ 0xAC,0xF9,0x51,0xAB,0xE3,0x01,0xDD,0xA5 } }; // 658D2F0E-63B7-4567-ACF9-51ABE301DDA5
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderQuotaUI>{ 0xBA6295C3,0x312E,0x544F,{ 0x9F,0xD5,0x1F,0x81,0xB2,0x1F,0x36,0x49 } }; // BA6295C3-312E-544F-9FD5-1F81B21F3649
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderStatusUI>{ 0xD6B6A758,0x198D,0x5B80,{ 0x97,0x7F,0x5F,0xF7,0x3D,0xA3,0x31,0x18 } }; // D6B6A758-198D-5B80-977F-5FF73DA33118
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource>{ 0xA306C249,0x3D66,0x5E70,{ 0x90,0x07,0xE4,0x3D,0xF9,0x60,0x51,0xFF } }; // A306C249-3D66-5E70-9007-E43DF96051FF
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory>{ 0x12E46B74,0x4E5A,0x58D1,{ 0xA6,0x2F,0x03,0x76,0xE8,0xEE,0x7D,0xD8 } }; // 12E46B74-4E5A-58D1-A62F-0376E8EE7DD8
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo>{ 0x7C1305C4,0x99F9,0x41AC,{ 0x89,0x04,0xAB,0x05,0x5D,0x65,0x49,0x26 } }; // 7C1305C4-99F9-41AC-8904-AB055D654926
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2>{ 0xCF51B023,0x7CF1,0x5166,{ 0xBD,0xBA,0xEF,0xD9,0x5F,0x52,0x9E,0x31 } }; // CF51B023-7CF1-5166-BDBA-EFD95F529E31
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3>{ 0x507A6617,0xBEF6,0x56FD,{ 0x85,0x5E,0x75,0xAC,0xE2,0xE4,0x5C,0xF5 } }; // 507A6617-BEF6-56FD-855E-75ACE2E45CF5
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>{ 0x3E99FBBF,0x8FE3,0x4B40,{ 0xAB,0xC7,0xF6,0xFC,0x3D,0x74,0xC9,0x8E } }; // 3E99FBBF-8FE3-4B40-ABC7-F6FC3D74C98E
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2>{ 0xEFB6CFEE,0x1374,0x544E,{ 0x9D,0xF1,0x55,0x98,0xD2,0xE9,0xCF,0xDD } }; // EFB6CFEE-1374-544E-9DF1-5598D2E9CFDD
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderUICommand>{ 0x0C3E0760,0xD846,0x568F,{ 0x94,0x84,0x10,0x5C,0xC5,0x7B,0x50,0x2B } }; // 0C3E0760-D846-568F-9484-105CC57B502B
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::IStorageProviderUriSource>{ 0xB29806D1,0x8BE0,0x4962,{ 0x8B,0xB6,0x0D,0x4C,0x2E,0x14,0xD4,0x7A } }; // B29806D1-8BE0-4962-8BB6-0D4C2E14D47A
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler>{ 0xC4CBB4F5,0x13DD,0x5C8E,{ 0x8B,0x96,0x33,0x6F,0xC3,0x0C,0x62,0x9B } }; // C4CBB4F5-13DD-5C8E-8B96-336FC30C629B
    template <> struct default_interface<winrt::Windows::Storage::Provider::CachedFileUpdaterUI>{ using type = winrt::Windows::Storage::Provider::ICachedFileUpdaterUI; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::FileUpdateRequest>{ using type = winrt::Windows::Storage::Provider::IFileUpdateRequest; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral>{ using type = winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs>{ using type = winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo>{ using type = winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult>{ using type = winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult>{ using type = winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderItemProperty>{ using type = winrt::Windows::Storage::Provider::IStorageProviderItemProperty; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition>{ using type = winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry>{ using type = winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo>{ using type = winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestArgs>{ using type = winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI>{ using type = winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderQuotaUI>{ using type = winrt::Windows::Storage::Provider::IStorageProviderQuotaUI; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderStatusUI>{ using type = winrt::Windows::Storage::Provider::IStorageProviderStatusUI; };
    template <> struct default_interface<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>{ using type = winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo; };
    template <> struct abi<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetUpdateInformation(void*, void*, int32_t, int32_t, uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall put_Title(void*) noexcept = 0;
            virtual int32_t __stdcall get_UpdateTarget(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_FileUpdateRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_FileUpdateRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_UIRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_UIRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_UIStatus(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UpdateRequest(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IFileUpdateRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContentId(void**) noexcept = 0;
            virtual int32_t __stdcall get_File(void**) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Status(int32_t) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
            virtual int32_t __stdcall UpdateLocalFile(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IFileUpdateRequest2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UserInputNeededMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_UserInputNeededMessage(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Complete() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FileExtension(void**) noexcept = 0;
            virtual int32_t __stdcall get_IconResource(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Status(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ContentUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_ContentUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_ContentId(void**) noexcept = 0;
            virtual int32_t __stdcall put_ContentId(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Status(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_Path(void**) noexcept = 0;
            virtual int32_t __stdcall put_Path(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderItemProperty>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_Id(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_Id(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Value(void*) noexcept = 0;
            virtual int32_t __stdcall get_Value(void**) noexcept = 0;
            virtual int32_t __stdcall put_IconResource(void*) noexcept = 0;
            virtual int32_t __stdcall get_IconResource(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Id(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_DisplayNameResource(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayNameResource(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetItemProperties(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_KnownFolderId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_KnownFolderId(winrt::guid) noexcept = 0;
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Status(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProviderDisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_ProviderDisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_KnownFolderEntries(void**) noexcept = 0;
            virtual int32_t __stdcall get_SyncRequested(void**) noexcept = 0;
            virtual int32_t __stdcall put_SyncRequested(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetKnownFolderSyncInfo(void**) noexcept = 0;
            virtual int32_t __stdcall add_KnownFolderSyncInfoChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_KnownFolderSyncInfoChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetKnownFolderSyncInfoSource(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_KnownFolders(void**) noexcept = 0;
            virtual int32_t __stdcall get_Source(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Message(void**) noexcept = 0;
            virtual int32_t __stdcall put_Message(void*) noexcept = 0;
            virtual int32_t __stdcall get_Command(void**) noexcept = 0;
            virtual int32_t __stdcall put_Command(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsPropertySupported(void*, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderQuotaUI>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_QuotaTotalInBytes(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall put_QuotaTotalInBytes(uint64_t) noexcept = 0;
            virtual int32_t __stdcall get_QuotaUsedInBytes(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall put_QuotaUsedInBytes(uint64_t) noexcept = 0;
            virtual int32_t __stdcall get_QuotaUsedLabel(void**) noexcept = 0;
            virtual int32_t __stdcall put_QuotaUsedLabel(void*) noexcept = 0;
            virtual int32_t __stdcall get_QuotaUsedColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_QuotaUsedColor(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderStatusUI>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProviderState(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ProviderState(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ProviderStateLabel(void**) noexcept = 0;
            virtual int32_t __stdcall put_ProviderStateLabel(void*) noexcept = 0;
            virtual int32_t __stdcall get_ProviderStateIcon(void**) noexcept = 0;
            virtual int32_t __stdcall put_ProviderStateIcon(void*) noexcept = 0;
            virtual int32_t __stdcall get_SyncStatusCommand(void**) noexcept = 0;
            virtual int32_t __stdcall put_SyncStatusCommand(void*) noexcept = 0;
            virtual int32_t __stdcall get_QuotaUI(void**) noexcept = 0;
            virtual int32_t __stdcall put_QuotaUI(void*) noexcept = 0;
            virtual int32_t __stdcall get_MoreInfoUI(void**) noexcept = 0;
            virtual int32_t __stdcall put_MoreInfoUI(void*) noexcept = 0;
            virtual int32_t __stdcall get_ProviderPrimaryCommand(void**) noexcept = 0;
            virtual int32_t __stdcall put_ProviderPrimaryCommand(void*) noexcept = 0;
            virtual int32_t __stdcall get_ProviderSecondaryCommands(void**) noexcept = 0;
            virtual int32_t __stdcall put_ProviderSecondaryCommands(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetStatusUI(void**) noexcept = 0;
            virtual int32_t __stdcall add_StatusUIChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StatusUIChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetStatusUISource(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall put_Id(void*) noexcept = 0;
            virtual int32_t __stdcall get_Context(void**) noexcept = 0;
            virtual int32_t __stdcall put_Context(void*) noexcept = 0;
            virtual int32_t __stdcall get_Path(void**) noexcept = 0;
            virtual int32_t __stdcall put_Path(void*) noexcept = 0;
            virtual int32_t __stdcall get_DisplayNameResource(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayNameResource(void*) noexcept = 0;
            virtual int32_t __stdcall get_IconResource(void**) noexcept = 0;
            virtual int32_t __stdcall put_IconResource(void*) noexcept = 0;
            virtual int32_t __stdcall get_HydrationPolicy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_HydrationPolicy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_HydrationPolicyModifier(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_HydrationPolicyModifier(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_PopulationPolicy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_PopulationPolicy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_InSyncPolicy(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_InSyncPolicy(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_HardlinkPolicy(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_HardlinkPolicy(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ShowSiblingsAsGroup(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ShowSiblingsAsGroup(bool) noexcept = 0;
            virtual int32_t __stdcall get_Version(void**) noexcept = 0;
            virtual int32_t __stdcall put_Version(void*) noexcept = 0;
            virtual int32_t __stdcall get_ProtectionMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ProtectionMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_AllowPinning(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowPinning(bool) noexcept = 0;
            virtual int32_t __stdcall get_StorageProviderItemPropertyDefinitions(void**) noexcept = 0;
            virtual int32_t __stdcall get_RecycleBinUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_RecycleBinUri(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ProviderId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall put_ProviderId(winrt::guid) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FallbackFileTypeInfo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Register(void*) noexcept = 0;
            virtual int32_t __stdcall Unregister(void*) noexcept = 0;
            virtual int32_t __stdcall GetSyncRootInformationForFolder(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetSyncRootInformationForId(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetCurrentSyncRoots(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderUICommand>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Label(void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_Icon(void**) noexcept = 0;
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall Invoke() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::IStorageProviderUriSource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetPathForContentUri(void*, void*) noexcept = 0;
            virtual int32_t __stdcall GetContentInfoForPath(void*, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_ICachedFileUpdaterStatics
    {
        WINRT_IMPL_AUTO(void) SetUpdateInformation(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contentId, winrt::Windows::Storage::Provider::ReadActivationMode const& readMode, winrt::Windows::Storage::Provider::WriteActivationMode const& writeMode, winrt::Windows::Storage::Provider::CachedFileOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_ICachedFileUpdaterStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_ICachedFileUpdaterUI
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        WINRT_IMPL_AUTO(void) Title(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::CachedFileTarget) UpdateTarget() const;
        WINRT_IMPL_AUTO(winrt::event_token) FileUpdateRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const;
        using FileUpdateRequested_revoker = impl::event_revoker<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI, &impl::abi_t<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI>::remove_FileUpdateRequested>;
        [[nodiscard]] FileUpdateRequested_revoker FileUpdateRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) FileUpdateRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) UIRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using UIRequested_revoker = impl::event_revoker<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI, &impl::abi_t<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI>::remove_UIRequested>;
        [[nodiscard]] UIRequested_revoker UIRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::CachedFileUpdaterUI, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) UIRequested(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::UIStatus) UIStatus() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_ICachedFileUpdaterUI2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequest) UpdateRequest() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequestDeferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_ICachedFileUpdaterUI2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IFileUpdateRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ContentId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) File() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateStatus) Status() const;
        WINRT_IMPL_AUTO(void) Status(winrt::Windows::Storage::Provider::FileUpdateStatus const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequestDeferral) GetDeferral() const;
        WINRT_IMPL_AUTO(void) UpdateLocalFile(winrt::Windows::Storage::IStorageFile const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IFileUpdateRequest>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IFileUpdateRequest2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UserInputNeededMessage() const;
        WINRT_IMPL_AUTO(void) UserInputNeededMessage(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IFileUpdateRequest2>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequest2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IFileUpdateRequestDeferral
    {
        WINRT_IMPL_AUTO(void) Complete() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequestDeferral<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IFileUpdateRequestedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::FileUpdateRequest) Request() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderFileTypeInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FileExtension() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) IconResource() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfo>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderFileTypeInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderFileTypeInfoFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo) CreateInstance(param::hstring const& fileExtension, param::hstring const& iconResource) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderFileTypeInfoFactory>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderFileTypeInfoFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus) Status() const;
        WINRT_IMPL_AUTO(void) Status(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ContentUri() const;
        WINRT_IMPL_AUTO(void) ContentUri(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ContentId() const;
        WINRT_IMPL_AUTO(void) ContentId(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus) Status() const;
        WINRT_IMPL_AUTO(void) Status(winrt::Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Path() const;
        WINRT_IMPL_AUTO(void) Path(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderItemPropertiesStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetAsync(winrt::Windows::Storage::IStorageItem const& item, param::async_iterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty> const& itemProperties) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemPropertiesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderItemProperty
    {
        WINRT_IMPL_AUTO(void) Id(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Id() const;
        WINRT_IMPL_AUTO(void) Value(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Value() const;
        WINRT_IMPL_AUTO(void) IconResource(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) IconResource() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderItemProperty>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Id() const;
        WINRT_IMPL_AUTO(void) Id(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayNameResource() const;
        WINRT_IMPL_AUTO(void) DisplayNameResource(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderItemPropertySource
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::Provider::StorageProviderItemProperty>) GetItemProperties(param::hstring const& itemPath) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemPropertySource<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderKnownFolderEntry
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) KnownFolderId() const;
        WINRT_IMPL_AUTO(void) KnownFolderId(winrt::guid const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus) Status() const;
        WINRT_IMPL_AUTO(void) Status(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncStatus const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderEntry>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderKnownFolderEntry<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ProviderDisplayName() const;
        WINRT_IMPL_AUTO(void) ProviderDisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderKnownFolderEntry>) KnownFolderEntries() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler) SyncRequested() const;
        WINRT_IMPL_AUTO(void) SyncRequested(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncRequestedHandler const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfo>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSource
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderKnownFolderSyncInfo) GetKnownFolderSyncInfo() const;
        WINRT_IMPL_AUTO(winrt::event_token) KnownFolderSyncInfoChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using KnownFolderSyncInfoChanged_revoker = impl::event_revoker<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource, &impl::abi_t<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource>::remove_KnownFolderSyncInfoChanged>;
        [[nodiscard]] KnownFolderSyncInfoChanged_revoker KnownFolderSyncInfoChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) KnownFolderSyncInfoChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSource<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSourceFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSource) GetKnownFolderSyncInfoSource() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncInfoSourceFactory>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncInfoSourceFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncRequestArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::guid>) KnownFolders() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) Source() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderKnownFolderSyncRequestArgs>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderKnownFolderSyncRequestArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderMoreInfoUI
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Message() const;
        WINRT_IMPL_AUTO(void) Message(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderUICommand) Command() const;
        WINRT_IMPL_AUTO(void) Command(winrt::Windows::Storage::Provider::IStorageProviderUICommand const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderMoreInfoUI>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderMoreInfoUI<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderPropertyCapabilities
    {
        WINRT_IMPL_AUTO(bool) IsPropertySupported(param::hstring const& propertyCanonicalName) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderPropertyCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderQuotaUI
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) QuotaTotalInBytes() const;
        WINRT_IMPL_AUTO(void) QuotaTotalInBytes(uint64_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) QuotaUsedInBytes() const;
        WINRT_IMPL_AUTO(void) QuotaUsedInBytes(uint64_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) QuotaUsedLabel() const;
        WINRT_IMPL_AUTO(void) QuotaUsedLabel(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) QuotaUsedColor() const;
        WINRT_IMPL_AUTO(void) QuotaUsedColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderQuotaUI>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderQuotaUI<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderStatusUI
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderState) ProviderState() const;
        WINRT_IMPL_AUTO(void) ProviderState(winrt::Windows::Storage::Provider::StorageProviderState const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ProviderStateLabel() const;
        WINRT_IMPL_AUTO(void) ProviderStateLabel(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ProviderStateIcon() const;
        WINRT_IMPL_AUTO(void) ProviderStateIcon(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderUICommand) SyncStatusCommand() const;
        WINRT_IMPL_AUTO(void) SyncStatusCommand(winrt::Windows::Storage::Provider::IStorageProviderUICommand const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderQuotaUI) QuotaUI() const;
        WINRT_IMPL_AUTO(void) QuotaUI(winrt::Windows::Storage::Provider::StorageProviderQuotaUI const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI) MoreInfoUI() const;
        WINRT_IMPL_AUTO(void) MoreInfoUI(winrt::Windows::Storage::Provider::StorageProviderMoreInfoUI const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderUICommand) ProviderPrimaryCommand() const;
        WINRT_IMPL_AUTO(void) ProviderPrimaryCommand(winrt::Windows::Storage::Provider::IStorageProviderUICommand const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::IStorageProviderUICommand>) ProviderSecondaryCommands() const;
        WINRT_IMPL_AUTO(void) ProviderSecondaryCommands(param::vector<winrt::Windows::Storage::Provider::IStorageProviderUICommand> const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderStatusUI>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderStatusUI<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderStatusUISource
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderStatusUI) GetStatusUI() const;
        WINRT_IMPL_AUTO(winrt::event_token) StatusUIChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using StatusUIChanged_revoker = impl::event_revoker<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource, &impl::abi_t<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource>::remove_StatusUIChanged>;
        [[nodiscard]] StatusUIChanged_revoker StatusUIChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) StatusUIChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderStatusUISource>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderStatusUISource<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderStatusUISourceFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::IStorageProviderStatusUISource) GetStatusUISource(param::hstring const& syncRootId) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderStatusUISourceFactory>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderStatusUISourceFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        WINRT_IMPL_AUTO(void) Id(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Context() const;
        WINRT_IMPL_AUTO(void) Context(winrt::Windows::Storage::Streams::IBuffer const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFolder) Path() const;
        WINRT_IMPL_AUTO(void) Path(winrt::Windows::Storage::IStorageFolder const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayNameResource() const;
        WINRT_IMPL_AUTO(void) DisplayNameResource(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) IconResource() const;
        WINRT_IMPL_AUTO(void) IconResource(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy) HydrationPolicy() const;
        WINRT_IMPL_AUTO(void) HydrationPolicy(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier) HydrationPolicyModifier() const;
        WINRT_IMPL_AUTO(void) HydrationPolicyModifier(winrt::Windows::Storage::Provider::StorageProviderHydrationPolicyModifier const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy) PopulationPolicy() const;
        WINRT_IMPL_AUTO(void) PopulationPolicy(winrt::Windows::Storage::Provider::StorageProviderPopulationPolicy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy) InSyncPolicy() const;
        WINRT_IMPL_AUTO(void) InSyncPolicy(winrt::Windows::Storage::Provider::StorageProviderInSyncPolicy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy) HardlinkPolicy() const;
        WINRT_IMPL_AUTO(void) HardlinkPolicy(winrt::Windows::Storage::Provider::StorageProviderHardlinkPolicy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowSiblingsAsGroup() const;
        WINRT_IMPL_AUTO(void) ShowSiblingsAsGroup(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Version() const;
        WINRT_IMPL_AUTO(void) Version(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderProtectionMode) ProtectionMode() const;
        WINRT_IMPL_AUTO(void) ProtectionMode(winrt::Windows::Storage::Provider::StorageProviderProtectionMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowPinning() const;
        WINRT_IMPL_AUTO(void) AllowPinning(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition>) StorageProviderItemPropertyDefinitions() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) RecycleBinUri() const;
        WINRT_IMPL_AUTO(void) RecycleBinUri(winrt::Windows::Foundation::Uri const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) ProviderId() const;
        WINRT_IMPL_AUTO(void) ProviderId(winrt::guid const& value) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Provider::StorageProviderFileTypeInfo>) FallbackFileTypeInfo() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo3>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo3<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics
    {
        WINRT_IMPL_AUTO(void) Register(winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo const& syncRootInformation) const;
        WINRT_IMPL_AUTO(void) Unregister(param::hstring const& id) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo) GetSyncRootInformationForFolder(winrt::Windows::Storage::IStorageFolder const& folder) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo) GetSyncRootInformationForId(param::hstring const& id) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo>) GetCurrentSyncRoots() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics2
    {
        WINRT_IMPL_AUTO(bool) IsSupported() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics2>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderUICommand
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Label() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Icon() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Provider::StorageProviderUICommandState) State() const;
        WINRT_IMPL_AUTO(void) Invoke() const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderUICommand>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderUICommand<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Provider_IStorageProviderUriSource
    {
        WINRT_IMPL_AUTO(void) GetPathForContentUri(param::hstring const& contentUri, winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult const& result) const;
        WINRT_IMPL_AUTO(void) GetContentInfoForPath(param::hstring const& path, winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult const& result) const;
    };
    template <> struct consume<winrt::Windows::Storage::Provider::IStorageProviderUriSource>
    {
        template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderUriSource<D>;
    };
}
#endif
