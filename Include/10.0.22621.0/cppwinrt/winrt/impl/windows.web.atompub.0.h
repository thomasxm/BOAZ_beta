// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_AtomPub_0_H
#define WINRT_Windows_Web_AtomPub_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename TProgress> struct __declspec(empty_bases) IAsyncActionWithProgress;
    template <typename TResult, typename TProgress> struct __declspec(empty_bases) IAsyncOperationWithProgress;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Security::Credentials
{
    struct PasswordCredential;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IInputStream;
}
WINRT_EXPORT namespace winrt::Windows::Web::Syndication
{
    struct ISyndicationText;
    struct RetrievalProgress;
    struct SyndicationCategory;
    struct SyndicationItem;
    struct TransferProgress;
}
WINRT_EXPORT namespace winrt::Windows::Web::AtomPub
{
    struct IAtomPubClient;
    struct IAtomPubClientFactory;
    struct IResourceCollection;
    struct IServiceDocument;
    struct IWorkspace;
    struct AtomPubClient;
    struct ResourceCollection;
    struct ServiceDocument;
    struct Workspace;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Web::AtomPub::IAtomPubClient>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::IAtomPubClientFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::IResourceCollection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::IServiceDocument>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::IWorkspace>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::AtomPubClient>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::ResourceCollection>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::ServiceDocument>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::AtomPub::Workspace>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::AtomPubClient> = L"Windows.Web.AtomPub.AtomPubClient";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::ResourceCollection> = L"Windows.Web.AtomPub.ResourceCollection";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::ServiceDocument> = L"Windows.Web.AtomPub.ServiceDocument";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::Workspace> = L"Windows.Web.AtomPub.Workspace";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::IAtomPubClient> = L"Windows.Web.AtomPub.IAtomPubClient";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::IAtomPubClientFactory> = L"Windows.Web.AtomPub.IAtomPubClientFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::IResourceCollection> = L"Windows.Web.AtomPub.IResourceCollection";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::IServiceDocument> = L"Windows.Web.AtomPub.IServiceDocument";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::AtomPub::IWorkspace> = L"Windows.Web.AtomPub.IWorkspace";
    template <> inline constexpr guid guid_v<winrt::Windows::Web::AtomPub::IAtomPubClient>{ 0x35392C38,0xCDED,0x4D4C,{ 0x96,0x37,0x05,0xF1,0x5C,0x1C,0x94,0x06 } }; // 35392C38-CDED-4D4C-9637-05F15C1C9406
    template <> inline constexpr guid guid_v<winrt::Windows::Web::AtomPub::IAtomPubClientFactory>{ 0x49D55012,0x57CB,0x4BDE,{ 0xAB,0x9F,0x26,0x10,0xB1,0x72,0x77,0x7B } }; // 49D55012-57CB-4BDE-AB9F-2610B172777B
    template <> inline constexpr guid guid_v<winrt::Windows::Web::AtomPub::IResourceCollection>{ 0x7F5FD609,0xBC88,0x41D4,{ 0x88,0xFA,0x3D,0xE6,0x70,0x4D,0x42,0x8E } }; // 7F5FD609-BC88-41D4-88FA-3DE6704D428E
    template <> inline constexpr guid guid_v<winrt::Windows::Web::AtomPub::IServiceDocument>{ 0x8B7EC771,0x2AB3,0x4DBE,{ 0x8B,0xCC,0x77,0x8F,0x92,0xB7,0x5E,0x51 } }; // 8B7EC771-2AB3-4DBE-8BCC-778F92B75E51
    template <> inline constexpr guid guid_v<winrt::Windows::Web::AtomPub::IWorkspace>{ 0xB41DA63B,0xA4B8,0x4036,{ 0x89,0xC5,0x83,0xC3,0x12,0x66,0xBA,0x49 } }; // B41DA63B-A4B8-4036-89C5-83C31266BA49
    template <> struct default_interface<winrt::Windows::Web::AtomPub::AtomPubClient>{ using type = winrt::Windows::Web::AtomPub::IAtomPubClient; };
    template <> struct default_interface<winrt::Windows::Web::AtomPub::ResourceCollection>{ using type = winrt::Windows::Web::AtomPub::IResourceCollection; };
    template <> struct default_interface<winrt::Windows::Web::AtomPub::ServiceDocument>{ using type = winrt::Windows::Web::AtomPub::IServiceDocument; };
    template <> struct default_interface<winrt::Windows::Web::AtomPub::Workspace>{ using type = winrt::Windows::Web::AtomPub::IWorkspace; };
    template <> struct abi<winrt::Windows::Web::AtomPub::IAtomPubClient>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RetrieveServiceDocumentAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RetrieveMediaResourceAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RetrieveResourceAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateResourceAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateMediaResourceAsync(void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateMediaResourceAsync(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateResourceAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateResourceItemAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteResourceAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteResourceItemAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CancelAsyncOperations() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::AtomPub::IAtomPubClientFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateAtomPubClientWithCredentials(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::AtomPub::IResourceCollection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_Uri(void**) noexcept = 0;
            virtual int32_t __stdcall get_Categories(void**) noexcept = 0;
            virtual int32_t __stdcall get_Accepts(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::AtomPub::IServiceDocument>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Workspaces(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::AtomPub::IWorkspace>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_Collections(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Web_AtomPub_IAtomPubClient
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Web::AtomPub::ServiceDocument, winrt::Windows::Web::Syndication::RetrievalProgress>) RetrieveServiceDocumentAsync(winrt::Windows::Foundation::Uri const& uri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IInputStream, winrt::Windows::Web::Syndication::RetrievalProgress>) RetrieveMediaResourceAsync(winrt::Windows::Foundation::Uri const& uri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Web::Syndication::SyndicationItem, winrt::Windows::Web::Syndication::RetrievalProgress>) RetrieveResourceAsync(winrt::Windows::Foundation::Uri const& uri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Web::Syndication::SyndicationItem, winrt::Windows::Web::Syndication::TransferProgress>) CreateResourceAsync(winrt::Windows::Foundation::Uri const& uri, param::hstring const& description, winrt::Windows::Web::Syndication::SyndicationItem const& item) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Web::Syndication::SyndicationItem, winrt::Windows::Web::Syndication::TransferProgress>) CreateMediaResourceAsync(winrt::Windows::Foundation::Uri const& uri, param::hstring const& mediaType, param::hstring const& description, winrt::Windows::Storage::Streams::IInputStream const& mediaStream) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncActionWithProgress<winrt::Windows::Web::Syndication::TransferProgress>) UpdateMediaResourceAsync(winrt::Windows::Foundation::Uri const& uri, param::hstring const& mediaType, winrt::Windows::Storage::Streams::IInputStream const& mediaStream) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncActionWithProgress<winrt::Windows::Web::Syndication::TransferProgress>) UpdateResourceAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Web::Syndication::SyndicationItem const& item) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncActionWithProgress<winrt::Windows::Web::Syndication::TransferProgress>) UpdateResourceItemAsync(winrt::Windows::Web::Syndication::SyndicationItem const& item) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncActionWithProgress<winrt::Windows::Web::Syndication::TransferProgress>) DeleteResourceAsync(winrt::Windows::Foundation::Uri const& uri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncActionWithProgress<winrt::Windows::Web::Syndication::TransferProgress>) DeleteResourceItemAsync(winrt::Windows::Web::Syndication::SyndicationItem const& item) const;
        WINRT_IMPL_AUTO(void) CancelAsyncOperations() const;
    };
    template <> struct consume<winrt::Windows::Web::AtomPub::IAtomPubClient>
    {
        template <typename D> using type = consume_Windows_Web_AtomPub_IAtomPubClient<D>;
    };
    template <typename D>
    struct consume_Windows_Web_AtomPub_IAtomPubClientFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Web::AtomPub::AtomPubClient) CreateAtomPubClientWithCredentials(winrt::Windows::Security::Credentials::PasswordCredential const& serverCredential) const;
    };
    template <> struct consume<winrt::Windows::Web::AtomPub::IAtomPubClientFactory>
    {
        template <typename D> using type = consume_Windows_Web_AtomPub_IAtomPubClientFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Web_AtomPub_IResourceCollection
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) Uri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Syndication::SyndicationCategory>) Categories() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Accepts() const;
    };
    template <> struct consume<winrt::Windows::Web::AtomPub::IResourceCollection>
    {
        template <typename D> using type = consume_Windows_Web_AtomPub_IResourceCollection<D>;
    };
    template <typename D>
    struct consume_Windows_Web_AtomPub_IServiceDocument
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::AtomPub::Workspace>) Workspaces() const;
    };
    template <> struct consume<winrt::Windows::Web::AtomPub::IServiceDocument>
    {
        template <typename D> using type = consume_Windows_Web_AtomPub_IServiceDocument<D>;
    };
    template <typename D>
    struct consume_Windows_Web_AtomPub_IWorkspace
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::AtomPub::ResourceCollection>) Collections() const;
    };
    template <> struct consume<winrt::Windows::Web::AtomPub::IWorkspace>
    {
        template <typename D> using type = consume_Windows_Web_AtomPub_IWorkspace<D>;
    };
}
#endif
