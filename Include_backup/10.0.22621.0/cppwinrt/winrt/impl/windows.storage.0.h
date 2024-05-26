// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_0_H
#define WINRT_Windows_Storage_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename T> struct __declspec(empty_bases) IObservableVector;
    struct IPropertySet;
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Storage::FileProperties
{
    struct BasicProperties;
    struct StorageItemContentProperties;
    struct StorageItemThumbnail;
    enum class ThumbnailMode : int32_t;
    enum class ThumbnailOptions : uint32_t;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Provider
{
    enum class FileUpdateStatus : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
    struct IOutputStream;
    struct IRandomAccessStream;
    struct IRandomAccessStreamReference;
    enum class UnicodeEncoding : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct User;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    enum class ApplicationDataCreateDisposition : int32_t
    {
        Always = 0,
        Existing = 1,
    };
    enum class ApplicationDataLocality : int32_t
    {
        Local = 0,
        Roaming = 1,
        Temporary = 2,
        LocalCache = 3,
        SharedLocal = 4,
    };
    enum class CreationCollisionOption : int32_t
    {
        GenerateUniqueName = 0,
        ReplaceExisting = 1,
        FailIfExists = 2,
        OpenIfExists = 3,
    };
    enum class FileAccessMode : int32_t
    {
        Read = 0,
        ReadWrite = 1,
    };
    enum class FileAttributes : uint32_t
    {
        Normal = 0,
        ReadOnly = 0x1,
        Directory = 0x10,
        Archive = 0x20,
        Temporary = 0x100,
        LocallyIncomplete = 0x200,
    };
    enum class KnownFolderId : int32_t
    {
        AppCaptures = 0,
        CameraRoll = 1,
        DocumentsLibrary = 2,
        HomeGroup = 3,
        MediaServerDevices = 4,
        MusicLibrary = 5,
        Objects3D = 6,
        PicturesLibrary = 7,
        Playlists = 8,
        RecordedCalls = 9,
        RemovableDevices = 10,
        SavedPictures = 11,
        Screenshots = 12,
        VideosLibrary = 13,
        AllAppMods = 14,
        CurrentAppMods = 15,
        DownloadsFolder = 16,
    };
    enum class KnownFoldersAccessStatus : int32_t
    {
        DeniedBySystem = 0,
        NotDeclaredByApp = 1,
        DeniedByUser = 2,
        UserPromptRequired = 3,
        Allowed = 4,
        AllowedPerAppFolder = 5,
    };
    enum class KnownLibraryId : int32_t
    {
        Music = 0,
        Pictures = 1,
        Videos = 2,
        Documents = 3,
    };
    enum class NameCollisionOption : int32_t
    {
        GenerateUniqueName = 0,
        ReplaceExisting = 1,
        FailIfExists = 2,
    };
    enum class StorageDeleteOption : int32_t
    {
        Default = 0,
        PermanentDelete = 1,
    };
    enum class StorageItemTypes : uint32_t
    {
        None = 0,
        File = 0x1,
        Folder = 0x2,
    };
    enum class StorageLibraryChangeType : int32_t
    {
        Created = 0,
        Deleted = 1,
        MovedOrRenamed = 2,
        ContentsChanged = 3,
        MovedOutOfLibrary = 4,
        MovedIntoLibrary = 5,
        ContentsReplaced = 6,
        IndexingStatusChanged = 7,
        EncryptionChanged = 8,
        ChangeTrackingLost = 9,
    };
    enum class StorageOpenOptions : uint32_t
    {
        None = 0,
        AllowOnlyReaders = 0x1,
        AllowReadersAndWriters = 0x2,
    };
    enum class StreamedFileFailureMode : int32_t
    {
        Failed = 0,
        CurrentlyUnavailable = 1,
        Incomplete = 2,
    };
    struct IAppDataPaths;
    struct IAppDataPathsStatics;
    struct IApplicationData;
    struct IApplicationData2;
    struct IApplicationData3;
    struct IApplicationDataContainer;
    struct IApplicationDataStatics;
    struct IApplicationDataStatics2;
    struct ICachedFileManagerStatics;
    struct IDownloadsFolderStatics;
    struct IDownloadsFolderStatics2;
    struct IFileIOStatics;
    struct IKnownFoldersCameraRollStatics;
    struct IKnownFoldersPlaylistsStatics;
    struct IKnownFoldersSavedPicturesStatics;
    struct IKnownFoldersStatics;
    struct IKnownFoldersStatics2;
    struct IKnownFoldersStatics3;
    struct IKnownFoldersStatics4;
    struct IPathIOStatics;
    struct ISetVersionDeferral;
    struct ISetVersionRequest;
    struct IStorageFile;
    struct IStorageFile2;
    struct IStorageFilePropertiesWithAvailability;
    struct IStorageFileStatics;
    struct IStorageFileStatics2;
    struct IStorageFolder;
    struct IStorageFolder2;
    struct IStorageFolder3;
    struct IStorageFolderStatics;
    struct IStorageFolderStatics2;
    struct IStorageItem;
    struct IStorageItem2;
    struct IStorageItemProperties;
    struct IStorageItemProperties2;
    struct IStorageItemPropertiesWithProvider;
    struct IStorageLibrary;
    struct IStorageLibrary2;
    struct IStorageLibrary3;
    struct IStorageLibraryChange;
    struct IStorageLibraryChangeReader;
    struct IStorageLibraryChangeReader2;
    struct IStorageLibraryChangeTracker;
    struct IStorageLibraryChangeTracker2;
    struct IStorageLibraryChangeTrackerOptions;
    struct IStorageLibraryLastChangeId;
    struct IStorageLibraryLastChangeIdStatics;
    struct IStorageLibraryStatics;
    struct IStorageLibraryStatics2;
    struct IStorageProvider;
    struct IStorageProvider2;
    struct IStorageStreamTransaction;
    struct IStreamedFileDataRequest;
    struct ISystemAudioProperties;
    struct ISystemDataPaths;
    struct ISystemDataPathsStatics;
    struct ISystemGPSProperties;
    struct ISystemImageProperties;
    struct ISystemMediaProperties;
    struct ISystemMusicProperties;
    struct ISystemPhotoProperties;
    struct ISystemProperties;
    struct ISystemVideoProperties;
    struct IUserDataPaths;
    struct IUserDataPathsStatics;
    struct AppDataPaths;
    struct ApplicationData;
    struct ApplicationDataCompositeValue;
    struct ApplicationDataContainer;
    struct ApplicationDataContainerSettings;
    struct CachedFileManager;
    struct DownloadsFolder;
    struct FileIO;
    struct KnownFolders;
    struct PathIO;
    struct SetVersionDeferral;
    struct SetVersionRequest;
    struct StorageFile;
    struct StorageFolder;
    struct StorageLibrary;
    struct StorageLibraryChange;
    struct StorageLibraryChangeReader;
    struct StorageLibraryChangeTracker;
    struct StorageLibraryChangeTrackerOptions;
    struct StorageLibraryLastChangeId;
    struct StorageProvider;
    struct StorageStreamTransaction;
    struct StreamedFileDataRequest;
    struct SystemAudioProperties;
    struct SystemDataPaths;
    struct SystemGPSProperties;
    struct SystemImageProperties;
    struct SystemMediaProperties;
    struct SystemMusicProperties;
    struct SystemPhotoProperties;
    struct SystemProperties;
    struct SystemVideoProperties;
    struct UserDataPaths;
    struct ApplicationDataSetVersionHandler;
    struct StreamedFileDataRequestedHandler;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Storage::IAppDataPaths>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IAppDataPathsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IApplicationData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IApplicationData2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IApplicationData3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IApplicationDataContainer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IApplicationDataStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IApplicationDataStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ICachedFileManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IDownloadsFolderStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IDownloadsFolderStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IFileIOStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IKnownFoldersCameraRollStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IKnownFoldersStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IKnownFoldersStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IKnownFoldersStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IKnownFoldersStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IPathIOStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISetVersionDeferral>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISetVersionRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFile>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFile2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFileStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFileStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFolder>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFolder2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFolder3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFolderStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageFolderStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageItem2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageItemProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageItemProperties2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageItemPropertiesWithProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibrary>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibrary2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibrary3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryChange>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryChangeReader>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryChangeReader2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryChangeTracker>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryChangeTracker2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryLastChangeId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageLibraryStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageProvider2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStorageStreamTransaction>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IStreamedFileDataRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemAudioProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemDataPaths>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemDataPathsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemGPSProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemImageProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemMediaProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemMusicProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemPhotoProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::ISystemVideoProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IUserDataPaths>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::IUserDataPathsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::AppDataPaths>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::ApplicationData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::ApplicationDataCompositeValue>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::ApplicationDataContainer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::ApplicationDataContainerSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::CachedFileManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::DownloadsFolder>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::FileIO>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::KnownFolders>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::PathIO>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SetVersionDeferral>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SetVersionRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageFile>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageFolder>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageLibrary>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageLibraryChange>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageLibraryChangeReader>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageLibraryChangeTracker>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageLibraryChangeTrackerOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageLibraryLastChangeId>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageProvider>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StorageStreamTransaction>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::StreamedFileDataRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemAudioProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemDataPaths>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemGPSProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemImageProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemMediaProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemMusicProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemPhotoProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::SystemVideoProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::UserDataPaths>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::ApplicationDataCreateDisposition>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::ApplicationDataLocality>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::CreationCollisionOption>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::FileAccessMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::FileAttributes>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::KnownFolderId>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::KnownFoldersAccessStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::KnownLibraryId>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::NameCollisionOption>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::StorageDeleteOption>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::StorageItemTypes>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::StorageLibraryChangeType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::StorageOpenOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::StreamedFileFailureMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::ApplicationDataSetVersionHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::Storage::StreamedFileDataRequestedHandler>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::AppDataPaths> = L"Windows.Storage.AppDataPaths";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ApplicationData> = L"Windows.Storage.ApplicationData";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ApplicationDataCompositeValue> = L"Windows.Storage.ApplicationDataCompositeValue";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ApplicationDataContainer> = L"Windows.Storage.ApplicationDataContainer";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ApplicationDataContainerSettings> = L"Windows.Storage.ApplicationDataContainerSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::CachedFileManager> = L"Windows.Storage.CachedFileManager";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::DownloadsFolder> = L"Windows.Storage.DownloadsFolder";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::FileIO> = L"Windows.Storage.FileIO";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::KnownFolders> = L"Windows.Storage.KnownFolders";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::PathIO> = L"Windows.Storage.PathIO";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SetVersionDeferral> = L"Windows.Storage.SetVersionDeferral";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SetVersionRequest> = L"Windows.Storage.SetVersionRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageFile> = L"Windows.Storage.StorageFile";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageFolder> = L"Windows.Storage.StorageFolder";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageLibrary> = L"Windows.Storage.StorageLibrary";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageLibraryChange> = L"Windows.Storage.StorageLibraryChange";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageLibraryChangeReader> = L"Windows.Storage.StorageLibraryChangeReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageLibraryChangeTracker> = L"Windows.Storage.StorageLibraryChangeTracker";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageLibraryChangeTrackerOptions> = L"Windows.Storage.StorageLibraryChangeTrackerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageLibraryLastChangeId> = L"Windows.Storage.StorageLibraryLastChangeId";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageProvider> = L"Windows.Storage.StorageProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageStreamTransaction> = L"Windows.Storage.StorageStreamTransaction";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StreamedFileDataRequest> = L"Windows.Storage.StreamedFileDataRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemAudioProperties> = L"Windows.Storage.SystemAudioProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemDataPaths> = L"Windows.Storage.SystemDataPaths";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemGPSProperties> = L"Windows.Storage.SystemGPSProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemImageProperties> = L"Windows.Storage.SystemImageProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemMediaProperties> = L"Windows.Storage.SystemMediaProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemMusicProperties> = L"Windows.Storage.SystemMusicProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemPhotoProperties> = L"Windows.Storage.SystemPhotoProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemProperties> = L"Windows.Storage.SystemProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::SystemVideoProperties> = L"Windows.Storage.SystemVideoProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::UserDataPaths> = L"Windows.Storage.UserDataPaths";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ApplicationDataCreateDisposition> = L"Windows.Storage.ApplicationDataCreateDisposition";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ApplicationDataLocality> = L"Windows.Storage.ApplicationDataLocality";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::CreationCollisionOption> = L"Windows.Storage.CreationCollisionOption";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::FileAccessMode> = L"Windows.Storage.FileAccessMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::FileAttributes> = L"Windows.Storage.FileAttributes";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::KnownFolderId> = L"Windows.Storage.KnownFolderId";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::KnownFoldersAccessStatus> = L"Windows.Storage.KnownFoldersAccessStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::KnownLibraryId> = L"Windows.Storage.KnownLibraryId";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::NameCollisionOption> = L"Windows.Storage.NameCollisionOption";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageDeleteOption> = L"Windows.Storage.StorageDeleteOption";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageItemTypes> = L"Windows.Storage.StorageItemTypes";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageLibraryChangeType> = L"Windows.Storage.StorageLibraryChangeType";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StorageOpenOptions> = L"Windows.Storage.StorageOpenOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StreamedFileFailureMode> = L"Windows.Storage.StreamedFileFailureMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IAppDataPaths> = L"Windows.Storage.IAppDataPaths";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IAppDataPathsStatics> = L"Windows.Storage.IAppDataPathsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IApplicationData> = L"Windows.Storage.IApplicationData";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IApplicationData2> = L"Windows.Storage.IApplicationData2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IApplicationData3> = L"Windows.Storage.IApplicationData3";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IApplicationDataContainer> = L"Windows.Storage.IApplicationDataContainer";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IApplicationDataStatics> = L"Windows.Storage.IApplicationDataStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IApplicationDataStatics2> = L"Windows.Storage.IApplicationDataStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ICachedFileManagerStatics> = L"Windows.Storage.ICachedFileManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IDownloadsFolderStatics> = L"Windows.Storage.IDownloadsFolderStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IDownloadsFolderStatics2> = L"Windows.Storage.IDownloadsFolderStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IFileIOStatics> = L"Windows.Storage.IFileIOStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IKnownFoldersCameraRollStatics> = L"Windows.Storage.IKnownFoldersCameraRollStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics> = L"Windows.Storage.IKnownFoldersPlaylistsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics> = L"Windows.Storage.IKnownFoldersSavedPicturesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IKnownFoldersStatics> = L"Windows.Storage.IKnownFoldersStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IKnownFoldersStatics2> = L"Windows.Storage.IKnownFoldersStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IKnownFoldersStatics3> = L"Windows.Storage.IKnownFoldersStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IKnownFoldersStatics4> = L"Windows.Storage.IKnownFoldersStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IPathIOStatics> = L"Windows.Storage.IPathIOStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISetVersionDeferral> = L"Windows.Storage.ISetVersionDeferral";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISetVersionRequest> = L"Windows.Storage.ISetVersionRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFile> = L"Windows.Storage.IStorageFile";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFile2> = L"Windows.Storage.IStorageFile2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability> = L"Windows.Storage.IStorageFilePropertiesWithAvailability";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFileStatics> = L"Windows.Storage.IStorageFileStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFileStatics2> = L"Windows.Storage.IStorageFileStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFolder> = L"Windows.Storage.IStorageFolder";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFolder2> = L"Windows.Storage.IStorageFolder2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFolder3> = L"Windows.Storage.IStorageFolder3";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFolderStatics> = L"Windows.Storage.IStorageFolderStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageFolderStatics2> = L"Windows.Storage.IStorageFolderStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageItem> = L"Windows.Storage.IStorageItem";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageItem2> = L"Windows.Storage.IStorageItem2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageItemProperties> = L"Windows.Storage.IStorageItemProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageItemProperties2> = L"Windows.Storage.IStorageItemProperties2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageItemPropertiesWithProvider> = L"Windows.Storage.IStorageItemPropertiesWithProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibrary> = L"Windows.Storage.IStorageLibrary";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibrary2> = L"Windows.Storage.IStorageLibrary2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibrary3> = L"Windows.Storage.IStorageLibrary3";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryChange> = L"Windows.Storage.IStorageLibraryChange";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryChangeReader> = L"Windows.Storage.IStorageLibraryChangeReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryChangeReader2> = L"Windows.Storage.IStorageLibraryChangeReader2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryChangeTracker> = L"Windows.Storage.IStorageLibraryChangeTracker";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryChangeTracker2> = L"Windows.Storage.IStorageLibraryChangeTracker2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions> = L"Windows.Storage.IStorageLibraryChangeTrackerOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryLastChangeId> = L"Windows.Storage.IStorageLibraryLastChangeId";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics> = L"Windows.Storage.IStorageLibraryLastChangeIdStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryStatics> = L"Windows.Storage.IStorageLibraryStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageLibraryStatics2> = L"Windows.Storage.IStorageLibraryStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageProvider> = L"Windows.Storage.IStorageProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageProvider2> = L"Windows.Storage.IStorageProvider2";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStorageStreamTransaction> = L"Windows.Storage.IStorageStreamTransaction";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IStreamedFileDataRequest> = L"Windows.Storage.IStreamedFileDataRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemAudioProperties> = L"Windows.Storage.ISystemAudioProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemDataPaths> = L"Windows.Storage.ISystemDataPaths";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemDataPathsStatics> = L"Windows.Storage.ISystemDataPathsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemGPSProperties> = L"Windows.Storage.ISystemGPSProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemImageProperties> = L"Windows.Storage.ISystemImageProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemMediaProperties> = L"Windows.Storage.ISystemMediaProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemMusicProperties> = L"Windows.Storage.ISystemMusicProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemPhotoProperties> = L"Windows.Storage.ISystemPhotoProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemProperties> = L"Windows.Storage.ISystemProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ISystemVideoProperties> = L"Windows.Storage.ISystemVideoProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IUserDataPaths> = L"Windows.Storage.IUserDataPaths";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::IUserDataPathsStatics> = L"Windows.Storage.IUserDataPathsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::ApplicationDataSetVersionHandler> = L"Windows.Storage.ApplicationDataSetVersionHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::StreamedFileDataRequestedHandler> = L"Windows.Storage.StreamedFileDataRequestedHandler";
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IAppDataPaths>{ 0x7301D60A,0x79A2,0x48C9,{ 0x9E,0xC0,0x3F,0xDA,0x09,0x2F,0x79,0xE1 } }; // 7301D60A-79A2-48C9-9EC0-3FDA092F79E1
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IAppDataPathsStatics>{ 0xD8EB2AFE,0xA9D9,0x4B14,{ 0xB9,0x99,0xE3,0x92,0x13,0x79,0xD9,0x03 } }; // D8EB2AFE-A9D9-4B14-B999-E3921379D903
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IApplicationData>{ 0xC3DA6FB7,0xB744,0x4B45,{ 0xB0,0xB8,0x22,0x3A,0x09,0x38,0xD0,0xDC } }; // C3DA6FB7-B744-4B45-B0B8-223A0938D0DC
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IApplicationData2>{ 0x9E65CD69,0x0BA3,0x4E32,{ 0xBE,0x29,0xB0,0x2D,0xE6,0x60,0x76,0x38 } }; // 9E65CD69-0BA3-4E32-BE29-B02DE6607638
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IApplicationData3>{ 0xDC222CF4,0x2772,0x4C1D,{ 0xAA,0x2C,0xC9,0xF7,0x43,0xAD,0xE8,0xD1 } }; // DC222CF4-2772-4C1D-AA2C-C9F743ADE8D1
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IApplicationDataContainer>{ 0xC5AEFD1E,0xF467,0x40BA,{ 0x85,0x66,0xAB,0x64,0x0A,0x44,0x1E,0x1D } }; // C5AEFD1E-F467-40BA-8566-AB640A441E1D
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IApplicationDataStatics>{ 0x5612147B,0xE843,0x45E3,{ 0x94,0xD8,0x06,0x16,0x9E,0x3C,0x8E,0x17 } }; // 5612147B-E843-45E3-94D8-06169E3C8E17
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IApplicationDataStatics2>{ 0xCD606211,0xCF49,0x40A4,{ 0xA4,0x7C,0xC7,0xF0,0xDB,0xBA,0x81,0x07 } }; // CD606211-CF49-40A4-A47C-C7F0DBBA8107
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ICachedFileManagerStatics>{ 0x8FFC224A,0xE782,0x495D,{ 0xB6,0x14,0x65,0x4C,0x4F,0x0B,0x23,0x70 } }; // 8FFC224A-E782-495D-B614-654C4F0B2370
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IDownloadsFolderStatics>{ 0x27862ED0,0x404E,0x47DF,{ 0xA1,0xE2,0xE3,0x73,0x08,0xBE,0x7B,0x37 } }; // 27862ED0-404E-47DF-A1E2-E37308BE7B37
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IDownloadsFolderStatics2>{ 0xE93045BD,0x8EF8,0x4F8E,{ 0x8D,0x15,0xAC,0x0E,0x26,0x5F,0x39,0x0D } }; // E93045BD-8EF8-4F8E-8D15-AC0E265F390D
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IFileIOStatics>{ 0x887411EB,0x7F54,0x4732,{ 0xA5,0xF0,0x5E,0x43,0xE3,0xB8,0xC2,0xF5 } }; // 887411EB-7F54-4732-A5F0-5E43E3B8C2F5
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IKnownFoldersCameraRollStatics>{ 0x5D115E66,0x27E8,0x492F,{ 0xB8,0xE5,0x2F,0x90,0x89,0x6C,0xD4,0xCD } }; // 5D115E66-27E8-492F-B8E5-2F90896CD4CD
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics>{ 0xDAD5ECD6,0x306F,0x4D6A,{ 0xB4,0x96,0x46,0xBA,0x8E,0xB1,0x06,0xCE } }; // DAD5ECD6-306F-4D6A-B496-46BA8EB106CE
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics>{ 0x055C93EA,0x253D,0x467C,{ 0xB6,0xCA,0xA9,0x7D,0xA1,0xE9,0xA1,0x8D } }; // 055C93EA-253D-467C-B6CA-A97DA1E9A18D
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IKnownFoldersStatics>{ 0x5A2A7520,0x4802,0x452D,{ 0x9A,0xD9,0x43,0x51,0xAD,0xA7,0xEC,0x35 } }; // 5A2A7520-4802-452D-9AD9-4351ADA7EC35
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IKnownFoldersStatics2>{ 0x194BD0CD,0xCF6E,0x4D07,{ 0x9D,0x53,0xE9,0x16,0x3A,0x25,0x36,0xE9 } }; // 194BD0CD-CF6E-4D07-9D53-E9163A2536E9
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IKnownFoldersStatics3>{ 0xC5194341,0x9742,0x4ED5,{ 0x82,0x3D,0xFC,0x14,0x01,0x14,0x87,0x64 } }; // C5194341-9742-4ED5-823D-FC1401148764
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IKnownFoldersStatics4>{ 0x1722E6BF,0x9FF9,0x4B21,{ 0xBE,0xD5,0x90,0xEC,0xB1,0x3A,0x19,0x2E } }; // 1722E6BF-9FF9-4B21-BED5-90ECB13A192E
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IPathIOStatics>{ 0x0F2F3758,0x8EC7,0x4381,{ 0x92,0x2B,0x8F,0x6C,0x07,0xD2,0x88,0xF3 } }; // 0F2F3758-8EC7-4381-922B-8F6C07D288F3
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISetVersionDeferral>{ 0x033508A2,0x781A,0x437A,{ 0xB0,0x78,0x3F,0x32,0xBA,0xDC,0xFE,0x47 } }; // 033508A2-781A-437A-B078-3F32BADCFE47
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISetVersionRequest>{ 0xB9C76B9B,0x1056,0x4E69,{ 0x83,0x30,0x16,0x26,0x19,0x95,0x6F,0x9B } }; // B9C76B9B-1056-4E69-8330-162619956F9B
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFile>{ 0xFA3F6186,0x4214,0x428C,{ 0xA6,0x4C,0x14,0xC9,0xAC,0x73,0x15,0xEA } }; // FA3F6186-4214-428C-A64C-14C9AC7315EA
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFile2>{ 0x954E4BCF,0x0A77,0x42FB,{ 0xB7,0x77,0xC2,0xED,0x58,0xA5,0x2E,0x44 } }; // 954E4BCF-0A77-42FB-B777-C2ED58A52E44
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability>{ 0xAFCBBE9B,0x582B,0x4133,{ 0x96,0x48,0xE4,0x4C,0xA4,0x6E,0xE4,0x91 } }; // AFCBBE9B-582B-4133-9648-E44CA46EE491
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFileStatics>{ 0x5984C710,0xDAF2,0x43C8,{ 0x8B,0xB4,0xA4,0xD3,0xEA,0xCF,0xD0,0x3F } }; // 5984C710-DAF2-43C8-8BB4-A4D3EACFD03F
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFileStatics2>{ 0x5C76A781,0x212E,0x4AF9,{ 0x8F,0x04,0x74,0x0C,0xAE,0x10,0x89,0x74 } }; // 5C76A781-212E-4AF9-8F04-740CAE108974
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFolder>{ 0x72D1CB78,0xB3EF,0x4F75,{ 0xA8,0x0B,0x6F,0xD9,0xDA,0xE2,0x94,0x4B } }; // 72D1CB78-B3EF-4F75-A80B-6FD9DAE2944B
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFolder2>{ 0xE827E8B9,0x08D9,0x4A8E,{ 0xA0,0xAC,0xFE,0x5E,0xD3,0xCB,0xBB,0xD3 } }; // E827E8B9-08D9-4A8E-A0AC-FE5ED3CBBBD3
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFolder3>{ 0x9F617899,0xBDE1,0x4124,{ 0xAE,0xB3,0xB0,0x6A,0xD9,0x6F,0x98,0xD4 } }; // 9F617899-BDE1-4124-AEB3-B06AD96F98D4
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFolderStatics>{ 0x08F327FF,0x85D5,0x48B9,{ 0xAE,0xE9,0x28,0x51,0x1E,0x33,0x9F,0x9F } }; // 08F327FF-85D5-48B9-AEE9-28511E339F9F
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageFolderStatics2>{ 0xB4656DC3,0x71D2,0x467D,{ 0x8B,0x29,0x37,0x1F,0x0F,0x62,0xBF,0x6F } }; // B4656DC3-71D2-467D-8B29-371F0F62BF6F
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageItem>{ 0x4207A996,0xCA2F,0x42F7,{ 0xBD,0xE8,0x8B,0x10,0x45,0x7A,0x7F,0x30 } }; // 4207A996-CA2F-42F7-BDE8-8B10457A7F30
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageItem2>{ 0x53F926D2,0x083C,0x4283,{ 0xB4,0x5B,0x81,0xC0,0x07,0x23,0x7E,0x44 } }; // 53F926D2-083C-4283-B45B-81C007237E44
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageItemProperties>{ 0x86664478,0x8029,0x46FE,{ 0xA7,0x89,0x1C,0x2F,0x3E,0x2F,0xFB,0x5C } }; // 86664478-8029-46FE-A789-1C2F3E2FFB5C
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageItemProperties2>{ 0x8E86A951,0x04B9,0x4BD2,{ 0x92,0x9D,0xFE,0xF3,0xF7,0x16,0x21,0xD0 } }; // 8E86A951-04B9-4BD2-929D-FEF3F71621D0
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageItemPropertiesWithProvider>{ 0x861BF39B,0x6368,0x4DEE,{ 0xB4,0x0E,0x74,0x68,0x4A,0x5C,0xE7,0x14 } }; // 861BF39B-6368-4DEE-B40E-74684A5CE714
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibrary>{ 0x1EDD7103,0x0E5E,0x4D6C,{ 0xB5,0xE8,0x93,0x18,0x98,0x3D,0x6A,0x03 } }; // 1EDD7103-0E5E-4D6C-B5E8-9318983D6A03
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibrary2>{ 0x5B0CE348,0xFCB3,0x4031,{ 0xAF,0xB0,0xA6,0x8D,0x7B,0xD4,0x45,0x34 } }; // 5B0CE348-FCB3-4031-AFB0-A68D7BD44534
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibrary3>{ 0x8A281291,0x2154,0x4201,{ 0x81,0x13,0xD2,0xC0,0x5C,0xE1,0xAD,0x23 } }; // 8A281291-2154-4201-8113-D2C05CE1AD23
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryChange>{ 0x00980B23,0x2BE2,0x4909,{ 0xAA,0x48,0x15,0x9F,0x52,0x03,0xA5,0x1E } }; // 00980B23-2BE2-4909-AA48-159F5203A51E
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryChangeReader>{ 0xF205BC83,0xFCA2,0x41F9,{ 0x89,0x54,0xEE,0x2E,0x99,0x1E,0xB9,0x6F } }; // F205BC83-FCA2-41F9-8954-EE2E991EB96F
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryChangeReader2>{ 0xABF4868B,0xFBCC,0x4A4F,{ 0x99,0x9E,0xE7,0xAB,0x7C,0x64,0x6D,0xBE } }; // ABF4868B-FBCC-4A4F-999E-E7AB7C646DBE
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryChangeTracker>{ 0x9E157316,0x6073,0x44F6,{ 0x96,0x81,0x74,0x92,0xD1,0x28,0x6C,0x90 } }; // 9E157316-6073-44F6-9681-7492D1286C90
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryChangeTracker2>{ 0xCD051C3B,0x0F9F,0x42F9,{ 0x8F,0xB3,0x15,0x8D,0x82,0xE1,0x38,0x21 } }; // CD051C3B-0F9F-42F9-8FB3-158D82E13821
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions>{ 0xBB52BCD4,0x1A6D,0x59C0,{ 0xAD,0x2A,0x82,0x3A,0x20,0x53,0x24,0x83 } }; // BB52BCD4-1A6D-59C0-AD2A-823A20532483
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryLastChangeId>{ 0x5281826A,0xBBE1,0x53BC,{ 0x82,0xCA,0x81,0xCC,0x7F,0x03,0x93,0x29 } }; // 5281826A-BBE1-53BC-82CA-81CC7F039329
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics>{ 0x81A49128,0x2CA3,0x5309,{ 0xB0,0xD1,0xCF,0x07,0x88,0xE4,0x07,0x62 } }; // 81A49128-2CA3-5309-B0D1-CF0788E40762
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryStatics>{ 0x4208A6DB,0x684A,0x49C6,{ 0x9E,0x59,0x90,0x12,0x1E,0xE0,0x50,0xD6 } }; // 4208A6DB-684A-49C6-9E59-90121EE050D6
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageLibraryStatics2>{ 0xFFB08DDC,0xFA75,0x4695,{ 0xB9,0xD1,0x7F,0x81,0xF9,0x78,0x32,0xE3 } }; // FFB08DDC-FA75-4695-B9D1-7F81F97832E3
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageProvider>{ 0xE705EED4,0xD478,0x47D6,{ 0xBA,0x46,0x1A,0x8E,0xBE,0x11,0x4A,0x20 } }; // E705EED4-D478-47D6-BA46-1A8EBE114A20
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageProvider2>{ 0x010D1917,0x3404,0x414B,{ 0x9F,0xD7,0xCD,0x44,0x47,0x2E,0xAA,0x39 } }; // 010D1917-3404-414B-9FD7-CD44472EAA39
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStorageStreamTransaction>{ 0xF67CF363,0xA53D,0x4D94,{ 0xAE,0x2C,0x67,0x23,0x2D,0x93,0xAC,0xDD } }; // F67CF363-A53D-4D94-AE2C-67232D93ACDD
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IStreamedFileDataRequest>{ 0x1673FCCE,0xDABD,0x4D50,{ 0xBE,0xEE,0x18,0x0B,0x8A,0x81,0x91,0xB6 } }; // 1673FCCE-DABD-4D50-BEEE-180B8A8191B6
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemAudioProperties>{ 0x3F8F38B7,0x308C,0x47E1,{ 0x92,0x4D,0x86,0x45,0x34,0x8E,0x5D,0xB7 } }; // 3F8F38B7-308C-47E1-924D-8645348E5DB7
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemDataPaths>{ 0xE32ABF70,0xD8FA,0x45EC,{ 0xA9,0x42,0xD2,0xE2,0x6F,0xB6,0x0B,0xA5 } }; // E32ABF70-D8FA-45EC-A942-D2E26FB60BA5
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemDataPathsStatics>{ 0xE0F96FD0,0x9920,0x4BCA,{ 0xB3,0x79,0xF9,0x6F,0xDF,0x7C,0xAA,0xD8 } }; // E0F96FD0-9920-4BCA-B379-F96FDF7CAAD8
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemGPSProperties>{ 0xC0F46EB4,0xC174,0x481A,{ 0xBC,0x25,0x92,0x19,0x86,0xF6,0xA6,0xF3 } }; // C0F46EB4-C174-481A-BC25-921986F6A6F3
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemImageProperties>{ 0x011B2E30,0x8B39,0x4308,{ 0xBE,0xA1,0xE8,0xAA,0x61,0xE4,0x78,0x26 } }; // 011B2E30-8B39-4308-BEA1-E8AA61E47826
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemMediaProperties>{ 0xA42B3316,0x8415,0x40DC,{ 0x8C,0x44,0x98,0x36,0x1D,0x23,0x54,0x30 } }; // A42B3316-8415-40DC-8C44-98361D235430
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemMusicProperties>{ 0xB47988D5,0x67AF,0x4BC3,{ 0x8D,0x39,0x5B,0x89,0x02,0x20,0x26,0xA1 } }; // B47988D5-67AF-4BC3-8D39-5B89022026A1
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemPhotoProperties>{ 0x4734FC3D,0xAB21,0x4424,{ 0xB7,0x35,0xF4,0x35,0x3A,0x56,0xC8,0xFC } }; // 4734FC3D-AB21-4424-B735-F4353A56C8FC
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemProperties>{ 0x917A71C1,0x85F3,0x4DD1,{ 0xB0,0x01,0xA5,0x0B,0xFD,0x21,0xC8,0xD2 } }; // 917A71C1-85F3-4DD1-B001-A50BFD21C8D2
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ISystemVideoProperties>{ 0x2040F715,0x67F8,0x4322,{ 0x9B,0x80,0x4F,0xA9,0xFE,0xFB,0x83,0xE8 } }; // 2040F715-67F8-4322-9B80-4FA9FEFB83E8
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IUserDataPaths>{ 0xF9C53912,0xABC4,0x46FF,{ 0x8A,0x2B,0xDC,0x9D,0x7F,0xA6,0xE5,0x2F } }; // F9C53912-ABC4-46FF-8A2B-DC9D7FA6E52F
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::IUserDataPathsStatics>{ 0x01B29DEF,0xE062,0x48A1,{ 0x8B,0x0C,0xF2,0xC7,0xA9,0xCA,0x56,0xC0 } }; // 01B29DEF-E062-48A1-8B0C-F2C7A9CA56C0
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::ApplicationDataSetVersionHandler>{ 0xA05791E6,0xCC9F,0x4687,{ 0xAC,0xAB,0xA3,0x64,0xFD,0x78,0x54,0x63 } }; // A05791E6-CC9F-4687-ACAB-A364FD785463
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::StreamedFileDataRequestedHandler>{ 0xFEF6A824,0x2FE1,0x4D07,{ 0xA3,0x5B,0xB7,0x7C,0x50,0xB5,0xF4,0xCC } }; // FEF6A824-2FE1-4D07-A35B-B77C50B5F4CC
    template <> struct default_interface<winrt::Windows::Storage::AppDataPaths>{ using type = winrt::Windows::Storage::IAppDataPaths; };
    template <> struct default_interface<winrt::Windows::Storage::ApplicationData>{ using type = winrt::Windows::Storage::IApplicationData; };
    template <> struct default_interface<winrt::Windows::Storage::ApplicationDataCompositeValue>{ using type = winrt::Windows::Foundation::Collections::IPropertySet; };
    template <> struct default_interface<winrt::Windows::Storage::ApplicationDataContainer>{ using type = winrt::Windows::Storage::IApplicationDataContainer; };
    template <> struct default_interface<winrt::Windows::Storage::ApplicationDataContainerSettings>{ using type = winrt::Windows::Foundation::Collections::IPropertySet; };
    template <> struct default_interface<winrt::Windows::Storage::SetVersionDeferral>{ using type = winrt::Windows::Storage::ISetVersionDeferral; };
    template <> struct default_interface<winrt::Windows::Storage::SetVersionRequest>{ using type = winrt::Windows::Storage::ISetVersionRequest; };
    template <> struct default_interface<winrt::Windows::Storage::StorageFile>{ using type = winrt::Windows::Storage::IStorageFile; };
    template <> struct default_interface<winrt::Windows::Storage::StorageFolder>{ using type = winrt::Windows::Storage::IStorageFolder; };
    template <> struct default_interface<winrt::Windows::Storage::StorageLibrary>{ using type = winrt::Windows::Storage::IStorageLibrary; };
    template <> struct default_interface<winrt::Windows::Storage::StorageLibraryChange>{ using type = winrt::Windows::Storage::IStorageLibraryChange; };
    template <> struct default_interface<winrt::Windows::Storage::StorageLibraryChangeReader>{ using type = winrt::Windows::Storage::IStorageLibraryChangeReader; };
    template <> struct default_interface<winrt::Windows::Storage::StorageLibraryChangeTracker>{ using type = winrt::Windows::Storage::IStorageLibraryChangeTracker; };
    template <> struct default_interface<winrt::Windows::Storage::StorageLibraryChangeTrackerOptions>{ using type = winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions; };
    template <> struct default_interface<winrt::Windows::Storage::StorageLibraryLastChangeId>{ using type = winrt::Windows::Storage::IStorageLibraryLastChangeId; };
    template <> struct default_interface<winrt::Windows::Storage::StorageProvider>{ using type = winrt::Windows::Storage::IStorageProvider; };
    template <> struct default_interface<winrt::Windows::Storage::StorageStreamTransaction>{ using type = winrt::Windows::Storage::IStorageStreamTransaction; };
    template <> struct default_interface<winrt::Windows::Storage::StreamedFileDataRequest>{ using type = winrt::Windows::Storage::Streams::IOutputStream; };
    template <> struct default_interface<winrt::Windows::Storage::SystemAudioProperties>{ using type = winrt::Windows::Storage::ISystemAudioProperties; };
    template <> struct default_interface<winrt::Windows::Storage::SystemDataPaths>{ using type = winrt::Windows::Storage::ISystemDataPaths; };
    template <> struct default_interface<winrt::Windows::Storage::SystemGPSProperties>{ using type = winrt::Windows::Storage::ISystemGPSProperties; };
    template <> struct default_interface<winrt::Windows::Storage::SystemImageProperties>{ using type = winrt::Windows::Storage::ISystemImageProperties; };
    template <> struct default_interface<winrt::Windows::Storage::SystemMediaProperties>{ using type = winrt::Windows::Storage::ISystemMediaProperties; };
    template <> struct default_interface<winrt::Windows::Storage::SystemMusicProperties>{ using type = winrt::Windows::Storage::ISystemMusicProperties; };
    template <> struct default_interface<winrt::Windows::Storage::SystemPhotoProperties>{ using type = winrt::Windows::Storage::ISystemPhotoProperties; };
    template <> struct default_interface<winrt::Windows::Storage::SystemVideoProperties>{ using type = winrt::Windows::Storage::ISystemVideoProperties; };
    template <> struct default_interface<winrt::Windows::Storage::UserDataPaths>{ using type = winrt::Windows::Storage::IUserDataPaths; };
    template <> struct abi<winrt::Windows::Storage::IAppDataPaths>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Cookies(void**) noexcept = 0;
            virtual int32_t __stdcall get_Desktop(void**) noexcept = 0;
            virtual int32_t __stdcall get_Documents(void**) noexcept = 0;
            virtual int32_t __stdcall get_Favorites(void**) noexcept = 0;
            virtual int32_t __stdcall get_History(void**) noexcept = 0;
            virtual int32_t __stdcall get_InternetCache(void**) noexcept = 0;
            virtual int32_t __stdcall get_LocalAppData(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProgramData(void**) noexcept = 0;
            virtual int32_t __stdcall get_RoamingAppData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IAppDataPathsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IApplicationData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Version(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall SetVersionAsync(uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ClearAllAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ClearAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall get_LocalSettings(void**) noexcept = 0;
            virtual int32_t __stdcall get_RoamingSettings(void**) noexcept = 0;
            virtual int32_t __stdcall get_LocalFolder(void**) noexcept = 0;
            virtual int32_t __stdcall get_RoamingFolder(void**) noexcept = 0;
            virtual int32_t __stdcall get_TemporaryFolder(void**) noexcept = 0;
            virtual int32_t __stdcall add_DataChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DataChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall SignalDataChanged() noexcept = 0;
            virtual int32_t __stdcall get_RoamingStorageQuota(uint64_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IApplicationData2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LocalCacheFolder(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IApplicationData3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetPublisherCacheFolder(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ClearPublisherCacheFolderAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_SharedLocalFolder(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IApplicationDataContainer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Locality(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Values(void**) noexcept = 0;
            virtual int32_t __stdcall get_Containers(void**) noexcept = 0;
            virtual int32_t __stdcall CreateContainer(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteContainer(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IApplicationDataStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Current(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IApplicationDataStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForUserAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ICachedFileManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall DeferUpdates(void*) noexcept = 0;
            virtual int32_t __stdcall CompleteUpdatesAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IDownloadsFolderStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFolderAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFileWithCollisionOptionAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFolderWithCollisionOptionAsync(void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IDownloadsFolderStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFileForUserAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFolderForUserAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFileForUserWithCollisionOptionAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFolderForUserWithCollisionOptionAsync(void*, void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IFileIOStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReadTextAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReadTextWithEncodingAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall WriteTextAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteTextWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall AppendTextAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AppendTextWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ReadLinesAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReadLinesWithEncodingAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall WriteLinesAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteLinesWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall AppendLinesAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AppendLinesWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ReadBufferAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteBufferAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteBytesAsync(void*, uint32_t, uint8_t*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IKnownFoldersCameraRollStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CameraRoll(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Playlists(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SavedPictures(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IKnownFoldersStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MusicLibrary(void**) noexcept = 0;
            virtual int32_t __stdcall get_PicturesLibrary(void**) noexcept = 0;
            virtual int32_t __stdcall get_VideosLibrary(void**) noexcept = 0;
            virtual int32_t __stdcall get_DocumentsLibrary(void**) noexcept = 0;
            virtual int32_t __stdcall get_HomeGroup(void**) noexcept = 0;
            virtual int32_t __stdcall get_RemovableDevices(void**) noexcept = 0;
            virtual int32_t __stdcall get_MediaServerDevices(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IKnownFoldersStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Objects3D(void**) noexcept = 0;
            virtual int32_t __stdcall get_AppCaptures(void**) noexcept = 0;
            virtual int32_t __stdcall get_RecordedCalls(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IKnownFoldersStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFolderForUserAsync(void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IKnownFoldersStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestAccessAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessForUserAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetFolderAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IPathIOStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReadTextAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReadTextWithEncodingAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall WriteTextAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteTextWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall AppendTextAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AppendTextWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ReadLinesAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReadLinesWithEncodingAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall WriteLinesAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteLinesWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall AppendLinesAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall AppendLinesWithEncodingAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ReadBufferAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteBufferAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall WriteBytesAsync(void*, uint32_t, uint8_t*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISetVersionDeferral>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Complete() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISetVersionRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CurrentVersion(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DesiredVersion(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall GetDeferral(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFile>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FileType(void**) noexcept = 0;
            virtual int32_t __stdcall get_ContentType(void**) noexcept = 0;
            virtual int32_t __stdcall OpenAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall OpenTransactedWriteAsync(void**) noexcept = 0;
            virtual int32_t __stdcall CopyOverloadDefaultNameAndOptions(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CopyOverloadDefaultOptions(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CopyOverload(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CopyAndReplaceAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall MoveOverloadDefaultNameAndOptions(void*, void**) noexcept = 0;
            virtual int32_t __stdcall MoveOverloadDefaultOptions(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall MoveOverload(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall MoveAndReplaceAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFile2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall OpenWithOptionsAsync(int32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall OpenTransactedWriteWithOptionsAsync(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsAvailable(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFileStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFileFromPathAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetFileFromApplicationUriAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateStreamedFileAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReplaceWithStreamedFileAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateStreamedFileFromUriAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReplaceWithStreamedFileFromUriAsync(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFileStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFileFromPathForUserAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFolder>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFileAsyncOverloadDefaultOptions(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFileAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFolderAsyncOverloadDefaultOptions(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFolderAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetFileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetFolderAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetItemAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetFilesAsyncOverloadDefaultOptionsStartAndCount(void**) noexcept = 0;
            virtual int32_t __stdcall GetFoldersAsyncOverloadDefaultOptionsStartAndCount(void**) noexcept = 0;
            virtual int32_t __stdcall GetItemsAsyncOverloadDefaultStartAndCount(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFolder2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryGetItemAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFolder3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryGetChangeTracker(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFolderStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFolderFromPathAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageFolderStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetFolderFromPathForUserAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RenameAsyncOverloadDefaultOptions(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RenameAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteAsyncOverloadDefaultOptions(void**) noexcept = 0;
            virtual int32_t __stdcall DeleteAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetBasicPropertiesAsync(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Path(void**) noexcept = 0;
            virtual int32_t __stdcall get_Attributes(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DateCreated(int64_t*) noexcept = 0;
            virtual int32_t __stdcall IsOfType(uint32_t, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageItem2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetParentAsync(void**) noexcept = 0;
            virtual int32_t __stdcall IsEqual(void*, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageItemProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetThumbnailAsyncOverloadDefaultSizeDefaultOptions(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetThumbnailAsyncOverloadDefaultOptions(int32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetThumbnailAsync(int32_t, uint32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall get_DisplayType(void**) noexcept = 0;
            virtual int32_t __stdcall get_FolderRelativeId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageItemProperties2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetScaledImageAsThumbnailAsyncOverloadDefaultSizeDefaultOptions(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetScaledImageAsThumbnailAsyncOverloadDefaultOptions(int32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetScaledImageAsThumbnailAsync(int32_t, uint32_t, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageItemPropertiesWithProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Provider(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibrary>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestAddFolderAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RequestRemoveFolderAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_Folders(void**) noexcept = 0;
            virtual int32_t __stdcall get_SaveFolder(void**) noexcept = 0;
            virtual int32_t __stdcall add_DefinitionChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DefinitionChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibrary2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ChangeTracker(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibrary3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AreFolderSuggestionsAvailableAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryChange>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ChangeType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Path(void**) noexcept = 0;
            virtual int32_t __stdcall get_PreviousPath(void**) noexcept = 0;
            virtual int32_t __stdcall IsOfType(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall GetStorageItemAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryChangeReader>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReadBatchAsync(void**) noexcept = 0;
            virtual int32_t __stdcall AcceptChangesAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryChangeReader2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetLastChangeId(uint64_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryChangeTracker>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetChangeReader(void**) noexcept = 0;
            virtual int32_t __stdcall Enable() noexcept = 0;
            virtual int32_t __stdcall Reset() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryChangeTracker2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall EnableWithOptions(void*) noexcept = 0;
            virtual int32_t __stdcall Disable() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TrackChangeDetails(bool*) noexcept = 0;
            virtual int32_t __stdcall put_TrackChangeDetails(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryLastChangeId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Unknown(uint64_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetLibraryAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageLibraryStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetLibraryForUserAsync(void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageProvider2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsPropertySupportedForPartialFileAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStorageStreamTransaction>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Stream(void**) noexcept = 0;
            virtual int32_t __stdcall CommitAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IStreamedFileDataRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FailAndClose(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemAudioProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EncodingBitrate(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemDataPaths>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Fonts(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProgramData(void**) noexcept = 0;
            virtual int32_t __stdcall get_Public(void**) noexcept = 0;
            virtual int32_t __stdcall get_PublicDesktop(void**) noexcept = 0;
            virtual int32_t __stdcall get_PublicDocuments(void**) noexcept = 0;
            virtual int32_t __stdcall get_PublicDownloads(void**) noexcept = 0;
            virtual int32_t __stdcall get_PublicMusic(void**) noexcept = 0;
            virtual int32_t __stdcall get_PublicPictures(void**) noexcept = 0;
            virtual int32_t __stdcall get_PublicVideos(void**) noexcept = 0;
            virtual int32_t __stdcall get_System(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemHost(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemX86(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemX64(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemArm(void**) noexcept = 0;
            virtual int32_t __stdcall get_UserProfiles(void**) noexcept = 0;
            virtual int32_t __stdcall get_Windows(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemDataPathsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemGPSProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LatitudeDecimal(void**) noexcept = 0;
            virtual int32_t __stdcall get_LongitudeDecimal(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemImageProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HorizontalSize(void**) noexcept = 0;
            virtual int32_t __stdcall get_VerticalSize(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemMediaProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Duration(void**) noexcept = 0;
            virtual int32_t __stdcall get_Producer(void**) noexcept = 0;
            virtual int32_t __stdcall get_Publisher(void**) noexcept = 0;
            virtual int32_t __stdcall get_SubTitle(void**) noexcept = 0;
            virtual int32_t __stdcall get_Writer(void**) noexcept = 0;
            virtual int32_t __stdcall get_Year(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemMusicProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AlbumArtist(void**) noexcept = 0;
            virtual int32_t __stdcall get_AlbumTitle(void**) noexcept = 0;
            virtual int32_t __stdcall get_Artist(void**) noexcept = 0;
            virtual int32_t __stdcall get_Composer(void**) noexcept = 0;
            virtual int32_t __stdcall get_Conductor(void**) noexcept = 0;
            virtual int32_t __stdcall get_DisplayArtist(void**) noexcept = 0;
            virtual int32_t __stdcall get_Genre(void**) noexcept = 0;
            virtual int32_t __stdcall get_TrackNumber(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemPhotoProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CameraManufacturer(void**) noexcept = 0;
            virtual int32_t __stdcall get_CameraModel(void**) noexcept = 0;
            virtual int32_t __stdcall get_DateTaken(void**) noexcept = 0;
            virtual int32_t __stdcall get_Orientation(void**) noexcept = 0;
            virtual int32_t __stdcall get_PeopleNames(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Author(void**) noexcept = 0;
            virtual int32_t __stdcall get_Comment(void**) noexcept = 0;
            virtual int32_t __stdcall get_ItemNameDisplay(void**) noexcept = 0;
            virtual int32_t __stdcall get_Keywords(void**) noexcept = 0;
            virtual int32_t __stdcall get_Rating(void**) noexcept = 0;
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_Audio(void**) noexcept = 0;
            virtual int32_t __stdcall get_GPS(void**) noexcept = 0;
            virtual int32_t __stdcall get_Media(void**) noexcept = 0;
            virtual int32_t __stdcall get_Music(void**) noexcept = 0;
            virtual int32_t __stdcall get_Photo(void**) noexcept = 0;
            virtual int32_t __stdcall get_Video(void**) noexcept = 0;
            virtual int32_t __stdcall get_Image(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ISystemVideoProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Director(void**) noexcept = 0;
            virtual int32_t __stdcall get_FrameHeight(void**) noexcept = 0;
            virtual int32_t __stdcall get_FrameWidth(void**) noexcept = 0;
            virtual int32_t __stdcall get_Orientation(void**) noexcept = 0;
            virtual int32_t __stdcall get_TotalBitrate(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IUserDataPaths>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CameraRoll(void**) noexcept = 0;
            virtual int32_t __stdcall get_Cookies(void**) noexcept = 0;
            virtual int32_t __stdcall get_Desktop(void**) noexcept = 0;
            virtual int32_t __stdcall get_Documents(void**) noexcept = 0;
            virtual int32_t __stdcall get_Downloads(void**) noexcept = 0;
            virtual int32_t __stdcall get_Favorites(void**) noexcept = 0;
            virtual int32_t __stdcall get_History(void**) noexcept = 0;
            virtual int32_t __stdcall get_InternetCache(void**) noexcept = 0;
            virtual int32_t __stdcall get_LocalAppData(void**) noexcept = 0;
            virtual int32_t __stdcall get_LocalAppDataLow(void**) noexcept = 0;
            virtual int32_t __stdcall get_Music(void**) noexcept = 0;
            virtual int32_t __stdcall get_Pictures(void**) noexcept = 0;
            virtual int32_t __stdcall get_Profile(void**) noexcept = 0;
            virtual int32_t __stdcall get_Recent(void**) noexcept = 0;
            virtual int32_t __stdcall get_RoamingAppData(void**) noexcept = 0;
            virtual int32_t __stdcall get_SavedPictures(void**) noexcept = 0;
            virtual int32_t __stdcall get_Screenshots(void**) noexcept = 0;
            virtual int32_t __stdcall get_Templates(void**) noexcept = 0;
            virtual int32_t __stdcall get_Videos(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::IUserDataPathsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForUser(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefault(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::ApplicationDataSetVersionHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::StreamedFileDataRequestedHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Storage_IAppDataPaths
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Cookies() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Desktop() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Documents() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Favorites() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) History() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) InternetCache() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LocalAppData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ProgramData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RoamingAppData() const;
    };
    template <> struct consume<winrt::Windows::Storage::IAppDataPaths>
    {
        template <typename D> using type = consume_Windows_Storage_IAppDataPaths<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IAppDataPathsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::AppDataPaths) GetForUser(winrt::Windows::System::User const& user) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::AppDataPaths) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Storage::IAppDataPathsStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IAppDataPathsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IApplicationData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Version() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetVersionAsync(uint32_t desiredVersion, winrt::Windows::Storage::ApplicationDataSetVersionHandler const& handler) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ClearAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ClearAsync(winrt::Windows::Storage::ApplicationDataLocality const& locality) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataContainer) LocalSettings() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataContainer) RoamingSettings() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) LocalFolder() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) RoamingFolder() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) TemporaryFolder() const;
        WINRT_IMPL_AUTO(winrt::event_token) DataChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::ApplicationData, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using DataChanged_revoker = impl::event_revoker<winrt::Windows::Storage::IApplicationData, &impl::abi_t<winrt::Windows::Storage::IApplicationData>::remove_DataChanged>;
        [[nodiscard]] DataChanged_revoker DataChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::ApplicationData, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) DataChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(void) SignalDataChanged() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) RoamingStorageQuota() const;
    };
    template <> struct consume<winrt::Windows::Storage::IApplicationData>
    {
        template <typename D> using type = consume_Windows_Storage_IApplicationData<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IApplicationData2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) LocalCacheFolder() const;
    };
    template <> struct consume<winrt::Windows::Storage::IApplicationData2>
    {
        template <typename D> using type = consume_Windows_Storage_IApplicationData2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IApplicationData3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) GetPublisherCacheFolder(param::hstring const& folderName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ClearPublisherCacheFolderAsync(param::hstring const& folderName) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) SharedLocalFolder() const;
    };
    template <> struct consume<winrt::Windows::Storage::IApplicationData3>
    {
        template <typename D> using type = consume_Windows_Storage_IApplicationData3<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IApplicationDataContainer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataLocality) Locality() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) Values() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Storage::ApplicationDataContainer>) Containers() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationDataContainer) CreateContainer(param::hstring const& name, winrt::Windows::Storage::ApplicationDataCreateDisposition const& disposition) const;
        WINRT_IMPL_AUTO(void) DeleteContainer(param::hstring const& name) const;
    };
    template <> struct consume<winrt::Windows::Storage::IApplicationDataContainer>
    {
        template <typename D> using type = consume_Windows_Storage_IApplicationDataContainer<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IApplicationDataStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::ApplicationData) Current() const;
    };
    template <> struct consume<winrt::Windows::Storage::IApplicationDataStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IApplicationDataStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IApplicationDataStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::ApplicationData>) GetForUserAsync(winrt::Windows::System::User const& user) const;
    };
    template <> struct consume<winrt::Windows::Storage::IApplicationDataStatics2>
    {
        template <typename D> using type = consume_Windows_Storage_IApplicationDataStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ICachedFileManagerStatics
    {
        WINRT_IMPL_AUTO(void) DeferUpdates(winrt::Windows::Storage::IStorageFile const& file) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Provider::FileUpdateStatus>) CompleteUpdatesAsync(winrt::Windows::Storage::IStorageFile const& file) const;
    };
    template <> struct consume<winrt::Windows::Storage::ICachedFileManagerStatics>
    {
        template <typename D> using type = consume_Windows_Storage_ICachedFileManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IDownloadsFolderStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateFileAsync(param::hstring const& desiredName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) CreateFolderAsync(param::hstring const& desiredName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateFileAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) CreateFolderAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const;
    };
    template <> struct consume<winrt::Windows::Storage::IDownloadsFolderStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IDownloadsFolderStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IDownloadsFolderStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateFileForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) CreateFolderForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateFileForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) CreateFolderForUserAsync(winrt::Windows::System::User const& user, param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& option) const;
    };
    template <> struct consume<winrt::Windows::Storage::IDownloadsFolderStatics2>
    {
        template <typename D> using type = consume_Windows_Storage_IDownloadsFolderStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IFileIOStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) ReadTextAsync(winrt::Windows::Storage::IStorageFile const& file) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) ReadTextAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendTextAsync(winrt::Windows::Storage::IStorageFile const& file, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) ReadLinesAsync(winrt::Windows::Storage::IStorageFile const& file) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) ReadLinesAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendLinesAsync(winrt::Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) ReadBufferAsync(winrt::Windows::Storage::IStorageFile const& file) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteBufferAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Storage::Streams::IBuffer const& buffer) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteBytesAsync(winrt::Windows::Storage::IStorageFile const& file, array_view<uint8_t const> buffer) const;
    };
    template <> struct consume<winrt::Windows::Storage::IFileIOStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IFileIOStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IKnownFoldersCameraRollStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) CameraRoll() const;
    };
    template <> struct consume<winrt::Windows::Storage::IKnownFoldersCameraRollStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IKnownFoldersCameraRollStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IKnownFoldersPlaylistsStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) Playlists() const;
    };
    template <> struct consume<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IKnownFoldersPlaylistsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IKnownFoldersSavedPicturesStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) SavedPictures() const;
    };
    template <> struct consume<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IKnownFoldersSavedPicturesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IKnownFoldersStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) MusicLibrary() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) PicturesLibrary() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) VideosLibrary() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) DocumentsLibrary() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) HomeGroup() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) RemovableDevices() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) MediaServerDevices() const;
    };
    template <> struct consume<winrt::Windows::Storage::IKnownFoldersStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IKnownFoldersStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IKnownFoldersStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) Objects3D() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) AppCaptures() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) RecordedCalls() const;
    };
    template <> struct consume<winrt::Windows::Storage::IKnownFoldersStatics2>
    {
        template <typename D> using type = consume_Windows_Storage_IKnownFoldersStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IKnownFoldersStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) GetFolderForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownFolderId const& folderId) const;
    };
    template <> struct consume<winrt::Windows::Storage::IKnownFoldersStatics3>
    {
        template <typename D> using type = consume_Windows_Storage_IKnownFoldersStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IKnownFoldersStatics4
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>) RequestAccessAsync(winrt::Windows::Storage::KnownFolderId const& folderId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::KnownFoldersAccessStatus>) RequestAccessForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownFolderId const& folderId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) GetFolderAsync(winrt::Windows::Storage::KnownFolderId const& folderId) const;
    };
    template <> struct consume<winrt::Windows::Storage::IKnownFoldersStatics4>
    {
        template <typename D> using type = consume_Windows_Storage_IKnownFoldersStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IPathIOStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) ReadTextAsync(param::hstring const& absolutePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) ReadTextAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) ReadLinesAsync(param::hstring const& absolutePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVector<hstring>>) ReadLinesAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, winrt::Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) ReadBufferAsync(param::hstring const& absolutePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteBufferAsync(param::hstring const& absolutePath, winrt::Windows::Storage::Streams::IBuffer const& buffer) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) WriteBytesAsync(param::hstring const& absolutePath, array_view<uint8_t const> buffer) const;
    };
    template <> struct consume<winrt::Windows::Storage::IPathIOStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IPathIOStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISetVersionDeferral
    {
        WINRT_IMPL_AUTO(void) Complete() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISetVersionDeferral>
    {
        template <typename D> using type = consume_Windows_Storage_ISetVersionDeferral<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISetVersionRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CurrentVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DesiredVersion() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::SetVersionDeferral) GetDeferral() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISetVersionRequest>
    {
        template <typename D> using type = consume_Windows_Storage_ISetVersionRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFile
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FileType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ContentType() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) OpenAsync(winrt::Windows::Storage::FileAccessMode const& accessMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) OpenTransactedWriteAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CopyAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CopyAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CopyAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName, winrt::Windows::Storage::NameCollisionOption const& option) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) CopyAndReplaceAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) MoveAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) MoveAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) MoveAsync(winrt::Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName, winrt::Windows::Storage::NameCollisionOption const& option) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) MoveAndReplaceAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFile>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFile<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFile2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) OpenAsync(winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) OpenTransactedWriteAsync(winrt::Windows::Storage::StorageOpenOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFile2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFile2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFilePropertiesWithAvailability
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAvailable() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFilePropertiesWithAvailability<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFileStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) GetFileFromPathAsync(param::hstring const& path) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) GetFileFromApplicationUriAsync(winrt::Windows::Foundation::Uri const& uri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateStreamedFileAsync(param::hstring const& displayNameWithExtension, winrt::Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) ReplaceWithStreamedFileAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace, winrt::Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateStreamedFileFromUriAsync(param::hstring const& displayNameWithExtension, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) ReplaceWithStreamedFileFromUriAsync(winrt::Windows::Storage::IStorageFile const& fileToReplace, winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFileStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFileStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFileStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) GetFileFromPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFileStatics2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFileStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFolder
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateFileAsync(param::hstring const& desiredName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) CreateFileAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) CreateFolderAsync(param::hstring const& desiredName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) CreateFolderAsync(param::hstring const& desiredName, winrt::Windows::Storage::CreationCollisionOption const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) GetFileAsync(param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) GetFolderAsync(param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>) GetItemAsync(param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFile>>) GetFilesAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFolder>>) GetFoldersAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::IStorageItem>>) GetItemsAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFolder>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFolder<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFolder2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>) TryGetItemAsync(param::hstring const& name) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFolder2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFolder2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFolder3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeTracker) TryGetChangeTracker() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFolder3>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFolder3<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFolderStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) GetFolderFromPathAsync(param::hstring const& path) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFolderStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFolderStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageFolderStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) GetFolderFromPathForUserAsync(winrt::Windows::System::User const& user, param::hstring const& path) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageFolderStatics2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageFolderStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageItem
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) RenameAsync(param::hstring const& desiredName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) RenameAsync(param::hstring const& desiredName, winrt::Windows::Storage::NameCollisionOption const& option) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DeleteAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DeleteAsync(winrt::Windows::Storage::StorageDeleteOption const& option) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::BasicProperties>) GetBasicPropertiesAsync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Path() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileAttributes) Attributes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) DateCreated() const;
        WINRT_IMPL_AUTO(bool) IsOfType(winrt::Windows::Storage::StorageItemTypes const& type) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageItem>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageItem<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageItem2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) GetParentAsync() const;
        WINRT_IMPL_AUTO(bool) IsEqual(winrt::Windows::Storage::IStorageItem const& item) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageItem2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageItem2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageItemProperties
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) GetThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) GetThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) GetThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& options) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FolderRelativeId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::StorageItemContentProperties) Properties() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageItemProperties>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageItemProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageItemProperties2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) GetScaledImageAsThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) GetScaledImageAsThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::FileProperties::StorageItemThumbnail>) GetScaledImageAsThumbnailAsync(winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageItemProperties2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageItemProperties2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageItemPropertiesWithProvider
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageProvider) Provider() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageItemPropertiesWithProvider>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageItemPropertiesWithProvider<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibrary
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) RequestAddFolderAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestRemoveFolderAsync(winrt::Windows::Storage::StorageFolder const& folder) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Storage::StorageFolder>) Folders() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) SaveFolder() const;
        WINRT_IMPL_AUTO(winrt::event_token) DefinitionChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::StorageLibrary, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using DefinitionChanged_revoker = impl::event_revoker<winrt::Windows::Storage::IStorageLibrary, &impl::abi_t<winrt::Windows::Storage::IStorageLibrary>::remove_DefinitionChanged>;
        [[nodiscard]] DefinitionChanged_revoker DefinitionChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::StorageLibrary, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) DefinitionChanged(winrt::event_token const& eventCookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibrary>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibrary<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibrary2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeTracker) ChangeTracker() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibrary2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibrary2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibrary3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) AreFolderSuggestionsAvailableAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibrary3>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibrary3<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryChange
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeType) ChangeType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Path() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PreviousPath() const;
        WINRT_IMPL_AUTO(bool) IsOfType(winrt::Windows::Storage::StorageItemTypes const& type) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::IStorageItem>) GetStorageItemAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryChange>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryChange<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryChangeReader
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageLibraryChange>>) ReadBatchAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AcceptChangesAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryChangeReader>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryChangeReader<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryChangeReader2
    {
        WINRT_IMPL_AUTO(uint64_t) GetLastChangeId() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryChangeReader2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryChangeReader2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryChangeTracker
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageLibraryChangeReader) GetChangeReader() const;
        WINRT_IMPL_AUTO(void) Enable() const;
        WINRT_IMPL_AUTO(void) Reset() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryChangeTracker>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryChangeTracker<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryChangeTracker2
    {
        WINRT_IMPL_AUTO(void) Enable(winrt::Windows::Storage::StorageLibraryChangeTrackerOptions const& options) const;
        WINRT_IMPL_AUTO(void) Disable() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryChangeTracker2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryChangeTracker2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryChangeTrackerOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) TrackChangeDetails() const;
        WINRT_IMPL_AUTO(void) TrackChangeDetails(bool value) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryChangeTrackerOptions>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryChangeTrackerOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryLastChangeId
    {
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryLastChangeId>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryLastChangeId<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryLastChangeIdStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) Unknown() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryLastChangeIdStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryLastChangeIdStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>) GetLibraryAsync(winrt::Windows::Storage::KnownLibraryId const& libraryId) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageLibraryStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageLibrary>) GetLibraryForUserAsync(winrt::Windows::System::User const& user, winrt::Windows::Storage::KnownLibraryId const& libraryId) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageLibraryStatics2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageLibraryStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageProvider
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageProvider>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageProvider<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageProvider2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) IsPropertySupportedForPartialFileAsync(param::hstring const& propertyCanonicalName) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageProvider2>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageProvider2<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStorageStreamTransaction
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStream) Stream() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) CommitAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::IStorageStreamTransaction>
    {
        template <typename D> using type = consume_Windows_Storage_IStorageStreamTransaction<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IStreamedFileDataRequest
    {
        WINRT_IMPL_AUTO(void) FailAndClose(winrt::Windows::Storage::StreamedFileFailureMode const& failureMode) const;
    };
    template <> struct consume<winrt::Windows::Storage::IStreamedFileDataRequest>
    {
        template <typename D> using type = consume_Windows_Storage_IStreamedFileDataRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemAudioProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EncodingBitrate() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemAudioProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemAudioProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemDataPaths
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Fonts() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ProgramData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Public() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PublicDesktop() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PublicDocuments() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PublicDownloads() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PublicMusic() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PublicPictures() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PublicVideos() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) System() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SystemHost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SystemX86() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SystemX64() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SystemArm() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UserProfiles() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Windows() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemDataPaths>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemDataPaths<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemDataPathsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemDataPaths) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemDataPathsStatics>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemDataPathsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemGPSProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LatitudeDecimal() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LongitudeDecimal() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemGPSProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemGPSProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemImageProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) HorizontalSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) VerticalSize() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemImageProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemImageProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemMediaProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Duration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Producer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Publisher() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SubTitle() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Writer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Year() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemMediaProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemMediaProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemMusicProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AlbumArtist() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AlbumTitle() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Artist() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Composer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Conductor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayArtist() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Genre() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TrackNumber() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemMusicProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemMusicProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemPhotoProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CameraManufacturer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CameraModel() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DateTaken() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Orientation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PeopleNames() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemPhotoProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemPhotoProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Author() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Comment() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ItemNameDisplay() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Keywords() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Rating() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemAudioProperties) Audio() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemGPSProperties) GPS() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemMediaProperties) Media() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemMusicProperties) Music() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemPhotoProperties) Photo() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemVideoProperties) Video() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::SystemImageProperties) Image() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_ISystemVideoProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Director() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FrameHeight() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FrameWidth() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Orientation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TotalBitrate() const;
    };
    template <> struct consume<winrt::Windows::Storage::ISystemVideoProperties>
    {
        template <typename D> using type = consume_Windows_Storage_ISystemVideoProperties<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IUserDataPaths
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CameraRoll() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Cookies() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Desktop() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Documents() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Downloads() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Favorites() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) History() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) InternetCache() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LocalAppData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LocalAppDataLow() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Music() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Pictures() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Profile() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Recent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RoamingAppData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) SavedPictures() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Screenshots() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Templates() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Videos() const;
    };
    template <> struct consume<winrt::Windows::Storage::IUserDataPaths>
    {
        template <typename D> using type = consume_Windows_Storage_IUserDataPaths<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_IUserDataPathsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::UserDataPaths) GetForUser(winrt::Windows::System::User const& user) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::UserDataPaths) GetDefault() const;
    };
    template <> struct consume<winrt::Windows::Storage::IUserDataPathsStatics>
    {
        template <typename D> using type = consume_Windows_Storage_IUserDataPathsStatics<D>;
    };
}
#endif
