// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_BulkAccess_0_H
#define WINRT_Windows_Storage_BulkAccess_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Storage::FileProperties
{
    struct BasicProperties;
    struct DocumentProperties;
    struct ImageProperties;
    struct MusicProperties;
    struct StorageItemThumbnail;
    enum class ThumbnailMode : int32_t;
    enum class ThumbnailOptions : uint32_t;
    struct VideoProperties;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Search
{
    struct IStorageQueryResultBase;
}
WINRT_EXPORT namespace winrt::Windows::Storage::BulkAccess
{
    struct IFileInformationFactory;
    struct IFileInformationFactoryFactory;
    struct IStorageItemInformation;
    struct FileInformation;
    struct FileInformationFactory;
    struct FolderInformation;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Storage::BulkAccess::IFileInformationFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::BulkAccess::IFileInformationFactoryFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::BulkAccess::FileInformation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::BulkAccess::FileInformationFactory>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::BulkAccess::FolderInformation>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::BulkAccess::FileInformation> = L"Windows.Storage.BulkAccess.FileInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::BulkAccess::FileInformationFactory> = L"Windows.Storage.BulkAccess.FileInformationFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::BulkAccess::FolderInformation> = L"Windows.Storage.BulkAccess.FolderInformation";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::BulkAccess::IFileInformationFactory> = L"Windows.Storage.BulkAccess.IFileInformationFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::BulkAccess::IFileInformationFactoryFactory> = L"Windows.Storage.BulkAccess.IFileInformationFactoryFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::BulkAccess::IStorageItemInformation> = L"Windows.Storage.BulkAccess.IStorageItemInformation";
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::BulkAccess::IFileInformationFactory>{ 0x401D88BE,0x960F,0x4D6D,{ 0xA7,0xD0,0x1A,0x38,0x61,0xE7,0x6C,0x83 } }; // 401D88BE-960F-4D6D-A7D0-1A3861E76C83
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::BulkAccess::IFileInformationFactoryFactory>{ 0x84EA0E7D,0xE4A2,0x4F00,{ 0x8A,0xFA,0xAF,0x5E,0x0F,0x82,0x6B,0xD5 } }; // 84EA0E7D-E4A2-4F00-8AFA-AF5E0F826BD5
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>{ 0x87A5CB8B,0x8972,0x4F40,{ 0x8D,0xE0,0xD8,0x6F,0xB1,0x79,0xD8,0xFA } }; // 87A5CB8B-8972-4F40-8DE0-D86FB179D8FA
    template <> struct default_interface<winrt::Windows::Storage::BulkAccess::FileInformation>{ using type = winrt::Windows::Storage::BulkAccess::IStorageItemInformation; };
    template <> struct default_interface<winrt::Windows::Storage::BulkAccess::FileInformationFactory>{ using type = winrt::Windows::Storage::BulkAccess::IFileInformationFactory; };
    template <> struct default_interface<winrt::Windows::Storage::BulkAccess::FolderInformation>{ using type = winrt::Windows::Storage::BulkAccess::IStorageItemInformation; };
    template <> struct abi<winrt::Windows::Storage::BulkAccess::IFileInformationFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetItemsAsync(uint32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetItemsAsyncDefaultStartAndCount(void**) noexcept = 0;
            virtual int32_t __stdcall GetFilesAsync(uint32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetFilesAsyncDefaultStartAndCount(void**) noexcept = 0;
            virtual int32_t __stdcall GetFoldersAsync(uint32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetFoldersAsyncDefaultStartAndCount(void**) noexcept = 0;
            virtual int32_t __stdcall GetVirtualizedItemsVector(void**) noexcept = 0;
            virtual int32_t __stdcall GetVirtualizedFilesVector(void**) noexcept = 0;
            virtual int32_t __stdcall GetVirtualizedFoldersVector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::BulkAccess::IFileInformationFactoryFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWithMode(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithModeAndSize(void*, int32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithModeAndSizeAndOptions(void*, int32_t, uint32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithModeAndSizeAndOptionsAndFlags(void*, int32_t, uint32_t, uint32_t, bool, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MusicProperties(void**) noexcept = 0;
            virtual int32_t __stdcall get_VideoProperties(void**) noexcept = 0;
            virtual int32_t __stdcall get_ImageProperties(void**) noexcept = 0;
            virtual int32_t __stdcall get_DocumentProperties(void**) noexcept = 0;
            virtual int32_t __stdcall get_BasicProperties(void**) noexcept = 0;
            virtual int32_t __stdcall get_Thumbnail(void**) noexcept = 0;
            virtual int32_t __stdcall add_ThumbnailUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ThumbnailUpdated(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PropertiesUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PropertiesUpdated(winrt::event_token) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Storage_BulkAccess_IFileInformationFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>>) GetItemsAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>>) GetItemsAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::BulkAccess::FileInformation>>) GetFilesAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::BulkAccess::FileInformation>>) GetFilesAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::BulkAccess::FolderInformation>>) GetFoldersAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::BulkAccess::FolderInformation>>) GetFoldersAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) GetVirtualizedItemsVector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) GetVirtualizedFilesVector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) GetVirtualizedFoldersVector() const;
    };
    template <> struct consume<winrt::Windows::Storage::BulkAccess::IFileInformationFactory>
    {
        template <typename D> using type = consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::BulkAccess::FileInformationFactory) CreateWithMode(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::BulkAccess::FileInformationFactory) CreateWithModeAndSize(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::BulkAccess::FileInformationFactory) CreateWithModeAndSizeAndOptions(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::BulkAccess::FileInformationFactory) CreateWithModeAndSizeAndOptionsAndFlags(winrt::Windows::Storage::Search::IStorageQueryResultBase const& queryResult, winrt::Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, winrt::Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions, bool delayLoad) const;
    };
    template <> struct consume<winrt::Windows::Storage::BulkAccess::IFileInformationFactoryFactory>
    {
        template <typename D> using type = consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_BulkAccess_IStorageItemInformation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::MusicProperties) MusicProperties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::VideoProperties) VideoProperties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::ImageProperties) ImageProperties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::DocumentProperties) DocumentProperties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::BasicProperties) BasicProperties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::StorageItemThumbnail) Thumbnail() const;
        WINRT_IMPL_AUTO(winrt::event_token) ThumbnailUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::BulkAccess::IStorageItemInformation, winrt::Windows::Foundation::IInspectable> const& changedHandler) const;
        using ThumbnailUpdated_revoker = impl::event_revoker<winrt::Windows::Storage::BulkAccess::IStorageItemInformation, &impl::abi_t<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>::remove_ThumbnailUpdated>;
        [[nodiscard]] ThumbnailUpdated_revoker ThumbnailUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::BulkAccess::IStorageItemInformation, winrt::Windows::Foundation::IInspectable> const& changedHandler) const;
        WINRT_IMPL_AUTO(void) ThumbnailUpdated(winrt::event_token const& eventCookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PropertiesUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::BulkAccess::IStorageItemInformation, winrt::Windows::Foundation::IInspectable> const& changedHandler) const;
        using PropertiesUpdated_revoker = impl::event_revoker<winrt::Windows::Storage::BulkAccess::IStorageItemInformation, &impl::abi_t<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>::remove_PropertiesUpdated>;
        [[nodiscard]] PropertiesUpdated_revoker PropertiesUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::BulkAccess::IStorageItemInformation, winrt::Windows::Foundation::IInspectable> const& changedHandler) const;
        WINRT_IMPL_AUTO(void) PropertiesUpdated(winrt::event_token const& eventCookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::Storage::BulkAccess::IStorageItemInformation>
    {
        template <typename D> using type = consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>;
    };
}
#endif
