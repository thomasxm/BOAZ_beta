// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_SocialInfo_0_H
#define WINRT_Windows_ApplicationModel_SocialInfo_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct IAsyncAction;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging
{
    struct BitmapSize;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IInputStream;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo
{
    enum class SocialFeedItemStyle : int32_t
    {
        Default = 0,
        Photo = 1,
    };
    enum class SocialFeedKind : int32_t
    {
        HomeFeed = 0,
        ContactFeed = 1,
        Dashboard = 2,
    };
    enum class SocialFeedUpdateMode : int32_t
    {
        Append = 0,
        Replace = 1,
    };
    enum class SocialItemBadgeStyle : int32_t
    {
        Hidden = 0,
        Visible = 1,
        VisibleWithCount = 2,
    };
    struct ISocialFeedChildItem;
    struct ISocialFeedContent;
    struct ISocialFeedItem;
    struct ISocialFeedSharedItem;
    struct ISocialItemThumbnail;
    struct ISocialUserInfo;
    struct SocialFeedChildItem;
    struct SocialFeedContent;
    struct SocialFeedItem;
    struct SocialFeedSharedItem;
    struct SocialItemThumbnail;
    struct SocialUserInfo;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedContent>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::ISocialUserInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedChildItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialUserInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedChildItem> = L"Windows.ApplicationModel.SocialInfo.SocialFeedChildItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent> = L"Windows.ApplicationModel.SocialInfo.SocialFeedContent";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedItem> = L"Windows.ApplicationModel.SocialInfo.SocialFeedItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem> = L"Windows.ApplicationModel.SocialInfo.SocialFeedSharedItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialItemThumbnail> = L"Windows.ApplicationModel.SocialInfo.SocialItemThumbnail";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialUserInfo> = L"Windows.ApplicationModel.SocialInfo.SocialUserInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle> = L"Windows.ApplicationModel.SocialInfo.SocialFeedItemStyle";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedKind> = L"Windows.ApplicationModel.SocialInfo.SocialFeedKind";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode> = L"Windows.ApplicationModel.SocialInfo.SocialFeedUpdateMode";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle> = L"Windows.ApplicationModel.SocialInfo.SocialItemBadgeStyle";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem> = L"Windows.ApplicationModel.SocialInfo.ISocialFeedChildItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedContent> = L"Windows.ApplicationModel.SocialInfo.ISocialFeedContent";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedItem> = L"Windows.ApplicationModel.SocialInfo.ISocialFeedItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem> = L"Windows.ApplicationModel.SocialInfo.ISocialFeedSharedItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail> = L"Windows.ApplicationModel.SocialInfo.ISocialItemThumbnail";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialUserInfo> = L"Windows.ApplicationModel.SocialInfo.ISocialUserInfo";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>{ 0x0B6A985A,0xD59D,0x40BE,{ 0x98,0x0C,0x48,0x8A,0x2A,0xB3,0x0A,0x83 } }; // 0B6A985A-D59D-40BE-980C-488A2AB30A83
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedContent>{ 0xA234E429,0x3E39,0x494D,{ 0xA3,0x7C,0xF4,0x62,0xA2,0x49,0x45,0x14 } }; // A234E429-3E39-494D-A37C-F462A2494514
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedItem>{ 0x4F1392AB,0x1F72,0x4D33,{ 0xB6,0x95,0xDE,0x3E,0x1D,0xB6,0x03,0x17 } }; // 4F1392AB-1F72-4D33-B695-DE3E1DB60317
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>{ 0x7BFB9E40,0xA6AA,0x45A7,{ 0x9F,0xF6,0x54,0xC4,0x21,0x05,0xDD,0x1F } }; // 7BFB9E40-A6AA-45A7-9FF6-54C42105DD1F
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>{ 0x5CBF831A,0x3F08,0x497F,{ 0x91,0x7F,0x57,0xE0,0x9D,0x84,0xB1,0x41 } }; // 5CBF831A-3F08-497F-917F-57E09D84B141
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::SocialInfo::ISocialUserInfo>{ 0x9E5E1BD1,0x90D0,0x4E1D,{ 0x95,0x54,0x84,0x4D,0x46,0x60,0x7F,0x61 } }; // 9E5E1BD1-90D0-4E1D-9554-844D46607F61
    template <> struct default_interface<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedChildItem>{ using type = winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent>{ using type = winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedContent; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedItem>{ using type = winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedItem; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem>{ using type = winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>{ using type = winrt::Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::SocialInfo::SocialUserInfo>{ using type = winrt::Windows::ApplicationModel::SocialInfo::ISocialUserInfo; };
    template <> struct abi<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Author(void**) noexcept = 0;
            virtual int32_t __stdcall get_PrimaryContent(void**) noexcept = 0;
            virtual int32_t __stdcall get_SecondaryContent(void**) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_Timestamp(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_TargetUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_Thumbnails(void**) noexcept = 0;
            virtual int32_t __stdcall get_SharedItem(void**) noexcept = 0;
            virtual int32_t __stdcall put_SharedItem(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedContent>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall put_Title(void*) noexcept = 0;
            virtual int32_t __stdcall get_Message(void**) noexcept = 0;
            virtual int32_t __stdcall put_Message(void*) noexcept = 0;
            virtual int32_t __stdcall get_TargetUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetUri(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Author(void**) noexcept = 0;
            virtual int32_t __stdcall get_PrimaryContent(void**) noexcept = 0;
            virtual int32_t __stdcall get_SecondaryContent(void**) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_Timestamp(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_TargetUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_Thumbnails(void**) noexcept = 0;
            virtual int32_t __stdcall get_SharedItem(void**) noexcept = 0;
            virtual int32_t __stdcall put_SharedItem(void*) noexcept = 0;
            virtual int32_t __stdcall get_BadgeStyle(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_BadgeStyle(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_BadgeCountValue(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_BadgeCountValue(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_RemoteId(void**) noexcept = 0;
            virtual int32_t __stdcall put_RemoteId(void*) noexcept = 0;
            virtual int32_t __stdcall get_ChildItem(void**) noexcept = 0;
            virtual int32_t __stdcall put_ChildItem(void*) noexcept = 0;
            virtual int32_t __stdcall get_Style(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Style(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_OriginalSource(void**) noexcept = 0;
            virtual int32_t __stdcall put_OriginalSource(void*) noexcept = 0;
            virtual int32_t __stdcall get_Content(void**) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_Timestamp(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_TargetUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetUri(void*) noexcept = 0;
            virtual int32_t __stdcall put_Thumbnail(void*) noexcept = 0;
            virtual int32_t __stdcall get_Thumbnail(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TargetUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_ImageUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_ImageUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_BitmapSize(struct struct_Windows_Graphics_Imaging_BitmapSize*) noexcept = 0;
            virtual int32_t __stdcall put_BitmapSize(struct struct_Windows_Graphics_Imaging_BitmapSize) noexcept = 0;
            virtual int32_t __stdcall SetImageAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::SocialInfo::ISocialUserInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_UserName(void**) noexcept = 0;
            virtual int32_t __stdcall put_UserName(void*) noexcept = 0;
            virtual int32_t __stdcall get_RemoteId(void**) noexcept = 0;
            virtual int32_t __stdcall put_RemoteId(void*) noexcept = 0;
            virtual int32_t __stdcall get_TargetUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_TargetUri(void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedChildItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialUserInfo) Author() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent) PrimaryContent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent) SecondaryContent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        WINRT_IMPL_AUTO(void) Timestamp(winrt::Windows::Foundation::DateTime const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) TargetUri() const;
        WINRT_IMPL_AUTO(void) TargetUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>) Thumbnails() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem) SharedItem() const;
        WINRT_IMPL_AUTO(void) SharedItem(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedChildItem<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedContent
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        WINRT_IMPL_AUTO(void) Title(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Message() const;
        WINRT_IMPL_AUTO(void) Message(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) TargetUri() const;
        WINRT_IMPL_AUTO(void) TargetUri(winrt::Windows::Foundation::Uri const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedContent>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedContent<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialUserInfo) Author() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent) PrimaryContent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent) SecondaryContent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        WINRT_IMPL_AUTO(void) Timestamp(winrt::Windows::Foundation::DateTime const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) TargetUri() const;
        WINRT_IMPL_AUTO(void) TargetUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>) Thumbnails() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem) SharedItem() const;
        WINRT_IMPL_AUTO(void) SharedItem(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle) BadgeStyle() const;
        WINRT_IMPL_AUTO(void) BadgeStyle(winrt::Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) BadgeCountValue() const;
        WINRT_IMPL_AUTO(void) BadgeCountValue(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RemoteId() const;
        WINRT_IMPL_AUTO(void) RemoteId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedChildItem) ChildItem() const;
        WINRT_IMPL_AUTO(void) ChildItem(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedChildItem const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle) Style() const;
        WINRT_IMPL_AUTO(void) Style(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedItem>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedItem<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedSharedItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) OriginalSource() const;
        WINRT_IMPL_AUTO(void) OriginalSource(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialFeedContent) Content() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        WINRT_IMPL_AUTO(void) Timestamp(winrt::Windows::Foundation::DateTime const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) TargetUri() const;
        WINRT_IMPL_AUTO(void) TargetUri(winrt::Windows::Foundation::Uri const& value) const;
        WINRT_IMPL_AUTO(void) Thumbnail(winrt::Windows::ApplicationModel::SocialInfo::SocialItemThumbnail const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::SocialInfo::SocialItemThumbnail) Thumbnail() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedSharedItem<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_SocialInfo_ISocialItemThumbnail
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) TargetUri() const;
        WINRT_IMPL_AUTO(void) TargetUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) ImageUri() const;
        WINRT_IMPL_AUTO(void) ImageUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::BitmapSize) BitmapSize() const;
        WINRT_IMPL_AUTO(void) BitmapSize(winrt::Windows::Graphics::Imaging::BitmapSize const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetImageAsync(winrt::Windows::Storage::Streams::IInputStream const& image) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialItemThumbnail<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_SocialInfo_ISocialUserInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        WINRT_IMPL_AUTO(void) DisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UserName() const;
        WINRT_IMPL_AUTO(void) UserName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RemoteId() const;
        WINRT_IMPL_AUTO(void) RemoteId(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) TargetUri() const;
        WINRT_IMPL_AUTO(void) TargetUri(winrt::Windows::Foundation::Uri const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::SocialInfo::ISocialUserInfo>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialUserInfo<D>;
    };
}
#endif
