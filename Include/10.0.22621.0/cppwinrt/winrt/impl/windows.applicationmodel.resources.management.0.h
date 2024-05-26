// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Resources_Management_0_H
#define WINRT_Windows_ApplicationModel_Resources_Management_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Management
{
    enum class IndexedResourceType : int32_t
    {
        String = 0,
        Path = 1,
        EmbeddedData = 2,
    };
    struct IIndexedResourceCandidate;
    struct IIndexedResourceQualifier;
    struct IResourceIndexer;
    struct IResourceIndexerFactory;
    struct IResourceIndexerFactory2;
    struct IndexedResourceCandidate;
    struct IndexedResourceQualifier;
    struct ResourceIndexer;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::ResourceIndexer>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceType>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate> = L"Windows.ApplicationModel.Resources.Management.IndexedResourceCandidate";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier> = L"Windows.ApplicationModel.Resources.Management.IndexedResourceQualifier";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::ResourceIndexer> = L"Windows.ApplicationModel.Resources.Management.ResourceIndexer";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceType> = L"Windows.ApplicationModel.Resources.Management.IndexedResourceType";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate> = L"Windows.ApplicationModel.Resources.Management.IIndexedResourceCandidate";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier> = L"Windows.ApplicationModel.Resources.Management.IIndexedResourceQualifier";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer> = L"Windows.ApplicationModel.Resources.Management.IResourceIndexer";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory> = L"Windows.ApplicationModel.Resources.Management.IResourceIndexerFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2> = L"Windows.ApplicationModel.Resources.Management.IResourceIndexerFactory2";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>{ 0x0E619EF3,0xFAEC,0x4414,{ 0xA9,0xD7,0x54,0xAC,0xD5,0x95,0x3F,0x29 } }; // 0E619EF3-FAEC-4414-A9D7-54ACD5953F29
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>{ 0xDAE3BB9B,0xD304,0x497F,{ 0xA1,0x68,0xA3,0x40,0x04,0x2C,0x8A,0xDB } }; // DAE3BB9B-D304-497F-A168-A340042C8ADB
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer>{ 0x2D4CF9A5,0xE32F,0x4AB2,{ 0x87,0x48,0x96,0x35,0x0A,0x01,0x6D,0xA3 } }; // 2D4CF9A5-E32F-4AB2-8748-96350A016DA3
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>{ 0xB8DE3F09,0x31CD,0x4D97,{ 0xBD,0x30,0x8D,0x39,0xF7,0x42,0xBC,0x61 } }; // B8DE3F09-31CD-4D97-BD30-8D39F742BC61
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>{ 0x6040F18D,0xD5E5,0x4B60,{ 0x92,0x01,0xCD,0x27,0x9C,0xBC,0xFE,0xD9 } }; // 6040F18D-D5E5-4B60-9201-CD279CBCFED9
    template <> struct default_interface<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate>{ using type = winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier>{ using type = winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Resources::Management::ResourceIndexer>{ using type = winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer; };
    template <> struct abi<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Type(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Uri(void**) noexcept = 0;
            virtual int32_t __stdcall get_Metadata(void**) noexcept = 0;
            virtual int32_t __stdcall get_Qualifiers(void**) noexcept = 0;
            virtual int32_t __stdcall get_ValueAsString(void**) noexcept = 0;
            virtual int32_t __stdcall GetQualifierValue(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_QualifierName(void**) noexcept = 0;
            virtual int32_t __stdcall get_QualifierValue(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IndexFilePath(void*, void**) noexcept = 0;
            virtual int32_t __stdcall IndexFileContentsAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateResourceIndexer(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateResourceIndexerWithExtension(void*, void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceCandidate
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceType) Type() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Uri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) Metadata() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceQualifier>) Qualifiers() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ValueAsString() const;
        WINRT_IMPL_AUTO(hstring) GetQualifierValue(param::hstring const& qualifierName) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceCandidate<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceQualifier
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) QualifierName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) QualifierValue() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IIndexedResourceQualifier<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Resources_Management_IResourceIndexer
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate) IndexFilePath(winrt::Windows::Foundation::Uri const& filePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Resources::Management::IndexedResourceCandidate>>) IndexFileContentsAsync(winrt::Windows::Foundation::Uri const& file) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexer>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IResourceIndexer<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Management::ResourceIndexer) CreateResourceIndexer(winrt::Windows::Foundation::Uri const& projectRoot) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory2
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Resources::Management::ResourceIndexer) CreateResourceIndexerWithExtension(winrt::Windows::Foundation::Uri const& projectRoot, winrt::Windows::Foundation::Uri const& extensionDllPath) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Resources::Management::IResourceIndexerFactory2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Resources_Management_IResourceIndexerFactory2<D>;
    };
}
#endif
