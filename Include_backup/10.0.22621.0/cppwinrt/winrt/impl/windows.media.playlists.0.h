// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Playlists_0_H
#define WINRT_Windows_Media_Playlists_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct IStorageFile;
    struct IStorageFolder;
    enum class NameCollisionOption : int32_t;
    struct StorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Media::Playlists
{
    enum class PlaylistFormat : int32_t
    {
        WindowsMedia = 0,
        Zune = 1,
        M3u = 2,
    };
    struct IPlaylist;
    struct IPlaylistStatics;
    struct Playlist;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Media::Playlists::IPlaylist>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Playlists::IPlaylistStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Media::Playlists::Playlist>{ using type = class_category; };
    template <> struct category<winrt::Windows::Media::Playlists::PlaylistFormat>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Playlists::Playlist> = L"Windows.Media.Playlists.Playlist";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Playlists::PlaylistFormat> = L"Windows.Media.Playlists.PlaylistFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Playlists::IPlaylist> = L"Windows.Media.Playlists.IPlaylist";
    template <> inline constexpr auto& name_v<winrt::Windows::Media::Playlists::IPlaylistStatics> = L"Windows.Media.Playlists.IPlaylistStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Playlists::IPlaylist>{ 0x803736F5,0xCF44,0x4D97,{ 0x83,0xB3,0x7A,0x08,0x9E,0x9A,0xB6,0x63 } }; // 803736F5-CF44-4D97-83B3-7A089E9AB663
    template <> inline constexpr guid guid_v<winrt::Windows::Media::Playlists::IPlaylistStatics>{ 0xC5C331CD,0x81F9,0x4FF3,{ 0x95,0xB9,0x70,0xB6,0xFF,0x04,0x6B,0x68 } }; // C5C331CD-81F9-4FF3-95B9-70B6FF046B68
    template <> struct default_interface<winrt::Windows::Media::Playlists::Playlist>{ using type = winrt::Windows::Media::Playlists::IPlaylist; };
    template <> struct abi<winrt::Windows::Media::Playlists::IPlaylist>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Files(void**) noexcept = 0;
            virtual int32_t __stdcall SaveAsync(void**) noexcept = 0;
            virtual int32_t __stdcall SaveAsAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SaveAsWithFormatAsync(void*, void*, int32_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Media::Playlists::IPlaylistStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall LoadAsync(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Media_Playlists_IPlaylist
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::StorageFile>) Files() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SaveAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) SaveAsAsync(winrt::Windows::Storage::IStorageFolder const& saveLocation, param::hstring const& desiredName, winrt::Windows::Storage::NameCollisionOption const& option) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) SaveAsAsync(winrt::Windows::Storage::IStorageFolder const& saveLocation, param::hstring const& desiredName, winrt::Windows::Storage::NameCollisionOption const& option, winrt::Windows::Media::Playlists::PlaylistFormat const& playlistFormat) const;
    };
    template <> struct consume<winrt::Windows::Media::Playlists::IPlaylist>
    {
        template <typename D> using type = consume_Windows_Media_Playlists_IPlaylist<D>;
    };
    template <typename D>
    struct consume_Windows_Media_Playlists_IPlaylistStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Playlists::Playlist>) LoadAsync(winrt::Windows::Storage::IStorageFile const& file) const;
    };
    template <> struct consume<winrt::Windows::Media::Playlists::IPlaylistStatics>
    {
        template <typename D> using type = consume_Windows_Media_Playlists_IPlaylistStatics<D>;
    };
}
#endif
