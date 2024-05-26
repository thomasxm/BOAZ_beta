// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Preview_Notes_0_H
#define WINRT_Windows_ApplicationModel_Preview_Notes_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct IAsyncAction;
    struct Size;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging
{
    struct SoftwareBitmap;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Notes
{
    struct INotePlacementChangedPreviewEventArgs;
    struct INoteVisibilityChangedPreviewEventArgs;
    struct INotesWindowManagerPreview;
    struct INotesWindowManagerPreview2;
    struct INotesWindowManagerPreviewShowNoteOptions;
    struct INotesWindowManagerPreviewStatics;
    struct NotePlacementChangedPreviewEventArgs;
    struct NoteVisibilityChangedPreviewEventArgs;
    struct NotesWindowManagerPreview;
    struct NotesWindowManagerPreviewShowNoteOptions;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> = L"Windows.ApplicationModel.Preview.Notes.NotePlacementChangedPreviewEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> = L"Windows.ApplicationModel.Preview.Notes.NoteVisibilityChangedPreviewEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview> = L"Windows.ApplicationModel.Preview.Notes.NotesWindowManagerPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions> = L"Windows.ApplicationModel.Preview.Notes.NotesWindowManagerPreviewShowNoteOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs> = L"Windows.ApplicationModel.Preview.Notes.INotePlacementChangedPreviewEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs> = L"Windows.ApplicationModel.Preview.Notes.INoteVisibilityChangedPreviewEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview> = L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreview";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2> = L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreview2";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions> = L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreviewShowNoteOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics> = L"Windows.ApplicationModel.Preview.Notes.INotesWindowManagerPreviewStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>{ 0x491D57B7,0xF780,0x4E7F,{ 0xA9,0x39,0x9A,0x4C,0xAF,0x96,0x52,0x14 } }; // 491D57B7-F780-4E7F-A939-9A4CAF965214
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>{ 0x0E34649E,0x3815,0x4FF6,{ 0x83,0xB3,0xA1,0x4D,0x17,0x12,0x0E,0x24 } }; // 0E34649E-3815-4FF6-83B3-A14D17120E24
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>{ 0xDC2AC23E,0x4850,0x4F13,{ 0x9C,0xC7,0xFF,0x48,0x7E,0xFD,0xFC,0xDE } }; // DC2AC23E-4850-4F13-9CC7-FF487EFDFCDE
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>{ 0xEDFE864A,0x1F54,0x4B09,{ 0x98,0x23,0xFF,0x47,0x7F,0x6F,0xA3,0xBC } }; // EDFE864A-1F54-4B09-9823-FF477F6FA3BC
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>{ 0x886B09D6,0xA6AE,0x4007,{ 0xA5,0x6D,0x1C,0xA7,0x0C,0x84,0xC0,0xD2 } }; // 886B09D6-A6AE-4007-A56D-1CA70C84C0D2
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>{ 0x6668CC88,0x0A8E,0x4127,{ 0xA3,0x8E,0x99,0x54,0x45,0x86,0x8A,0x78 } }; // 6668CC88-0A8E-4127-A38E-995445868A78
    template <> struct default_interface<winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs>{ using type = winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs>{ using type = winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview>{ using type = winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions>{ using type = winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions; };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ViewId(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ViewId(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsVisible(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsScreenLocked(bool*) noexcept = 0;
            virtual int32_t __stdcall ShowNote(int32_t) noexcept = 0;
            virtual int32_t __stdcall ShowNoteRelativeTo(int32_t, int32_t) noexcept = 0;
            virtual int32_t __stdcall ShowNoteWithPlacement(int32_t, void*) noexcept = 0;
            virtual int32_t __stdcall HideNote(int32_t) noexcept = 0;
            virtual int32_t __stdcall GetNotePlacement(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TrySetNoteSize(int32_t, winrt::Windows::Foundation::Size, bool*) noexcept = 0;
            virtual int32_t __stdcall SetFocusToNextView() noexcept = 0;
            virtual int32_t __stdcall SetNotesThumbnailAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_SystemLockStateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SystemLockStateChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_NotePlacementChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_NotePlacementChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_NoteVisibilityChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_NoteVisibilityChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ShowNoteRelativeToWithOptions(int32_t, int32_t, void*) noexcept = 0;
            virtual int32_t __stdcall ShowNoteWithPlacementWithOptions(int32_t, void*, void*) noexcept = 0;
            virtual int32_t __stdcall SetFocusToPreviousView() noexcept = 0;
            virtual int32_t __stdcall SetThumbnailImageForTaskSwitcherAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ShowWithFocus(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ShowWithFocus(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentApp(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Notes_INotePlacementChangedPreviewEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ViewId() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotePlacementChangedPreviewEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Notes_INoteVisibilityChangedPreviewEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ViewId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsVisible() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INoteVisibilityChangedPreviewEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScreenLocked() const;
        WINRT_IMPL_AUTO(void) ShowNote(int32_t noteViewId) const;
        WINRT_IMPL_AUTO(void) ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId) const;
        WINRT_IMPL_AUTO(void) ShowNoteWithPlacement(int32_t noteViewId, winrt::Windows::Storage::Streams::IBuffer const& data) const;
        WINRT_IMPL_AUTO(void) HideNote(int32_t noteViewId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) GetNotePlacement(int32_t noteViewId) const;
        WINRT_IMPL_AUTO(bool) TrySetNoteSize(int32_t noteViewId, winrt::Windows::Foundation::Size const& size) const;
        WINRT_IMPL_AUTO(void) SetFocusToNextView() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetNotesThumbnailAsync(winrt::Windows::Storage::Streams::IBuffer const& thumbnail) const;
        WINRT_IMPL_AUTO(winrt::event_token) SystemLockStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using SystemLockStateChanged_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview, &impl::abi_t<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>::remove_SystemLockStateChanged>;
        [[nodiscard]] SystemLockStateChanged_revoker SystemLockStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) SystemLockStateChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) NotePlacementChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> const& handler) const;
        using NotePlacementChanged_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview, &impl::abi_t<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>::remove_NotePlacementChanged>;
        [[nodiscard]] NotePlacementChanged_revoker NotePlacementChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) NotePlacementChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) NoteVisibilityChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> const& handler) const;
        using NoteVisibilityChanged_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview, &impl::abi_t<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>::remove_NoteVisibilityChanged>;
        [[nodiscard]] NoteVisibilityChanged_revoker NoteVisibilityChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) NoteVisibilityChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2
    {
        WINRT_IMPL_AUTO(void) ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId, winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const& options) const;
        WINRT_IMPL_AUTO(void) ShowNoteWithPlacement(int32_t noteViewId, winrt::Windows::Storage::Streams::IBuffer const& data, winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const& options) const;
        WINRT_IMPL_AUTO(void) SetFocusToPreviousView() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetThumbnailImageForTaskSwitcherAsync(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewShowNoteOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowWithFocus() const;
        WINRT_IMPL_AUTO(void) ShowWithFocus(bool value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewShowNoteOptions<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview) GetForCurrentApp() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewStatics<D>;
    };
}
#endif
