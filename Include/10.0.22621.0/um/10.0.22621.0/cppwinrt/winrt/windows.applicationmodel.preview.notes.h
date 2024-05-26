// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Preview_Notes_H
#define WINRT_Windows_ApplicationModel_Preview_Notes_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.Notes.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Preview_Notes_INotePlacementChangedPreviewEventArgs<D>::ViewId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs)->get_ViewId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_ApplicationModel_Preview_Notes_INoteVisibilityChangedPreviewEventArgs<D>::ViewId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs)->get_ViewId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Preview_Notes_INoteVisibilityChangedPreviewEventArgs<D>::IsVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs)->get_IsVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::IsScreenLocked() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->get_IsScreenLocked(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::ShowNote(int32_t noteViewId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->ShowNote(noteViewId));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->ShowNoteRelativeTo(noteViewId, anchorNoteViewId));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::ShowNoteWithPlacement(int32_t noteViewId, winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->ShowNoteWithPlacement(noteViewId, *(void**)(&data)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::HideNote(int32_t noteViewId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->HideNote(noteViewId));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::GetNotePlacement(int32_t noteViewId) const
    {
        void* data{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->GetNotePlacement(noteViewId, &data));
        return winrt::Windows::Storage::Streams::IBuffer{ data, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::TrySetNoteSize(int32_t noteViewId, winrt::Windows::Foundation::Size const& size) const
    {
        bool succeeded{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->TrySetNoteSize(noteViewId, impl::bind_in(size), &succeeded));
        return succeeded;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::SetFocusToNextView() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->SetFocusToNextView());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::SetNotesThumbnailAsync(winrt::Windows::Storage::Streams::IBuffer const& thumbnail) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->SetNotesThumbnailAsync(*(void**)(&thumbnail), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::SystemLockStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->add_SystemLockStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::SystemLockStateChanged_revoker consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::SystemLockStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SystemLockStateChanged_revoker>(this, SystemLockStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::SystemLockStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->remove_SystemLockStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NotePlacementChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->add_NotePlacementChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NotePlacementChanged_revoker consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NotePlacementChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NotePlacementChanged_revoker>(this, NotePlacementChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NotePlacementChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->remove_NotePlacementChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NoteVisibilityChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->add_NoteVisibilityChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NoteVisibilityChanged_revoker consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NoteVisibilityChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, NoteVisibilityChanged_revoker>(this, NoteVisibilityChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview<D>::NoteVisibilityChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview)->remove_NoteVisibilityChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2<D>::ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId, winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2)->ShowNoteRelativeToWithOptions(noteViewId, anchorNoteViewId, *(void**)(&options)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2<D>::ShowNoteWithPlacement(int32_t noteViewId, winrt::Windows::Storage::Streams::IBuffer const& data, winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2)->ShowNoteWithPlacementWithOptions(noteViewId, *(void**)(&data), *(void**)(&options)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2<D>::SetFocusToPreviousView() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2)->SetFocusToPreviousView());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreview2<D>::SetThumbnailImageForTaskSwitcherAsync(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2)->SetThumbnailImageForTaskSwitcherAsync(*(void**)(&bitmap), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewShowNoteOptions<D>::ShowWithFocus() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions)->get_ShowWithFocus(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewShowNoteOptions<D>::ShowWithFocus(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions)->put_ShowWithFocus(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview) consume_Windows_ApplicationModel_Preview_Notes_INotesWindowManagerPreviewStatics<D>::GetForCurrentApp() const
    {
        void* current{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics)->GetForCurrentApp(&current));
        return winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview{ current, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs>
    {
        int32_t __stdcall get_ViewId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ViewId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs>
    {
        int32_t __stdcall get_ViewId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ViewId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview> : produce_base<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview>
    {
        int32_t __stdcall get_IsScreenLocked(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsScreenLocked());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowNote(int32_t noteViewId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowNote(noteViewId);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowNoteRelativeTo(int32_t noteViewId, int32_t anchorNoteViewId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowNoteRelativeTo(noteViewId, anchorNoteViewId);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowNoteWithPlacement(int32_t noteViewId, void* data) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowNoteWithPlacement(noteViewId, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HideNote(int32_t noteViewId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HideNote(noteViewId);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNotePlacement(int32_t noteViewId, void** data) noexcept final try
        {
            clear_abi(data);
            typename D::abi_guard guard(this->shim());
            *data = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().GetNotePlacement(noteViewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetNoteSize(int32_t noteViewId, winrt::Windows::Foundation::Size size, bool* succeeded) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *succeeded = detach_from<bool>(this->shim().TrySetNoteSize(noteViewId, *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFocusToNextView() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFocusToNextView();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetNotesThumbnailAsync(void* thumbnail, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetNotesThumbnailAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SystemLockStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SystemLockStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SystemLockStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SystemLockStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NotePlacementChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NotePlacementChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NotePlacementChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotePlacementChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_NoteVisibilityChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().NoteVisibilityChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview, winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_NoteVisibilityChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NoteVisibilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2> : produce_base<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2>
    {
        int32_t __stdcall ShowNoteRelativeToWithOptions(int32_t noteViewId, int32_t anchorNoteViewId, void* options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowNoteRelativeTo(noteViewId, anchorNoteViewId, *reinterpret_cast<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowNoteWithPlacementWithOptions(int32_t noteViewId, void* data, void* options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowNoteWithPlacement(noteViewId, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data), *reinterpret_cast<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFocusToPreviousView() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFocusToPreviousView();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetThumbnailImageForTaskSwitcherAsync(void* bitmap, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetThumbnailImageForTaskSwitcherAsync(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions> : produce_base<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions>
    {
        int32_t __stdcall get_ShowWithFocus(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShowWithFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShowWithFocus(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowWithFocus(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics> : produce_base<D, winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics>
    {
        int32_t __stdcall GetForCurrentApp(void** current) noexcept final try
        {
            clear_abi(current);
            typename D::abi_guard guard(this->shim());
            *current = detach_from<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview>(this->shim().GetForCurrentApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Notes
{
    inline auto NotesWindowManagerPreview::GetForCurrentApp()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview(*)(INotesWindowManagerPreviewStatics const&), NotesWindowManagerPreview, INotesWindowManagerPreviewStatics>([](INotesWindowManagerPreviewStatics const& f) { return f.GetForCurrentApp(); });
    }
    inline NotesWindowManagerPreviewShowNoteOptions::NotesWindowManagerPreviewShowNoteOptions() :
        NotesWindowManagerPreviewShowNoteOptions(impl::call_factory_cast<NotesWindowManagerPreviewShowNoteOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), NotesWindowManagerPreviewShowNoteOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<NotesWindowManagerPreviewShowNoteOptions>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::INotePlacementChangedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::INoteVisibilityChangedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreview2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewShowNoteOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::INotesWindowManagerPreviewStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::NotePlacementChangedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::NoteVisibilityChangedPreviewEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreview> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Preview::Notes::NotesWindowManagerPreviewShowNoteOptions> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
