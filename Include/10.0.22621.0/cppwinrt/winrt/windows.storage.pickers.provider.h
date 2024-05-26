// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Pickers_Provider_H
#define WINRT_Windows_Storage_Pickers_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Storage.Pickers.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Pickers.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::Provider::AddFileResult) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::AddFile(param::hstring const& id, winrt::Windows::Storage::IStorageFile const& file) const
    {
        winrt::Windows::Storage::Pickers::Provider::AddFileResult addResult{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->AddFile(*(void**)(&id), *(void**)(&file), reinterpret_cast<int32_t*>(&addResult)));
        return addResult;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::RemoveFile(param::hstring const& id) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->RemoveFile(*(void**)(&id)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::ContainsFile(param::hstring const& id) const
    {
        bool isContained{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->ContainsFile(*(void**)(&id), &isContained));
        return isContained;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::CanAddFile(winrt::Windows::Storage::IStorageFile const& file) const
    {
        bool canAdd{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->CanAddFile(*(void**)(&file), &canAdd));
        return canAdd;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::AllowedFileTypes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->get_AllowedFileTypes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::Provider::FileSelectionMode) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::SelectionMode() const
    {
        winrt::Windows::Storage::Pickers::Provider::FileSelectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->get_SelectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::SettingsIdentifier() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->get_SettingsIdentifier(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::FileRemoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileOpenPickerUI, winrt::Windows::Storage::Pickers::Provider::FileRemovedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->add_FileRemoved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::FileRemoved_revoker consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::FileRemoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileOpenPickerUI, winrt::Windows::Storage::Pickers::Provider::FileRemovedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FileRemoved_revoker>(this, FileRemoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::FileRemoved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->remove_FileRemoved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::Closing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileOpenPickerUI, winrt::Windows::Storage::Pickers::Provider::PickerClosingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->add_Closing(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::Closing_revoker consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::Closing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileOpenPickerUI, winrt::Windows::Storage::Pickers::Provider::PickerClosingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closing_revoker>(this, Closing(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IFileOpenPickerUI<D>::Closing(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI)->remove_Closing(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_Provider_IFileRemovedEventArgs<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileRemovedEventArgs)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::AllowedFileTypes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->get_AllowedFileTypes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::SettingsIdentifier() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->get_SettingsIdentifier(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::FileName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->get_FileName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::Provider::SetFileNameResult) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::TrySetFileName(param::hstring const& value) const
    {
        winrt::Windows::Storage::Pickers::Provider::SetFileNameResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->TrySetFileName(*(void**)(&value), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::FileNameChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileSavePickerUI, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->add_FileNameChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::FileNameChanged_revoker consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::FileNameChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileSavePickerUI, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, FileNameChanged_revoker>(this, FileNameChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::FileNameChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->remove_FileNameChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::TargetFileRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileSavePickerUI, winrt::Windows::Storage::Pickers::Provider::TargetFileRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->add_TargetFileRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::TargetFileRequested_revoker consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::TargetFileRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileSavePickerUI, winrt::Windows::Storage::Pickers::Provider::TargetFileRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TargetFileRequested_revoker>(this, TargetFileRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IFileSavePickerUI<D>::TargetFileRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI)->remove_TargetFileRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_IPickerClosingDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IPickerClosingDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::Provider::PickerClosingOperation) consume_Windows_Storage_Pickers_Provider_IPickerClosingEventArgs<D>::ClosingOperation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IPickerClosingEventArgs)->get_ClosingOperation(&value));
        return winrt::Windows::Storage::Pickers::Provider::PickerClosingOperation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Pickers_Provider_IPickerClosingEventArgs<D>::IsCanceled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IPickerClosingEventArgs)->get_IsCanceled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::Provider::PickerClosingDeferral) consume_Windows_Storage_Pickers_Provider_IPickerClosingOperation<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IPickerClosingOperation)->GetDeferral(&value));
        return winrt::Windows::Storage::Pickers::Provider::PickerClosingDeferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Storage_Pickers_Provider_IPickerClosingOperation<D>::Deadline() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::IPickerClosingOperation)->get_Deadline(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFile) consume_Windows_Storage_Pickers_Provider_ITargetFileRequest<D>::TargetFile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::ITargetFileRequest)->get_TargetFile(&value));
        return winrt::Windows::Storage::IStorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_ITargetFileRequest<D>::TargetFile(winrt::Windows::Storage::IStorageFile const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::ITargetFileRequest)->put_TargetFile(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::Provider::TargetFileRequestDeferral) consume_Windows_Storage_Pickers_Provider_ITargetFileRequest<D>::GetDeferral() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::ITargetFileRequest)->GetDeferral(&value));
        return winrt::Windows::Storage::Pickers::Provider::TargetFileRequestDeferral{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_Provider_ITargetFileRequestDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::Provider::TargetFileRequest) consume_Windows_Storage_Pickers_Provider_ITargetFileRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::Storage::Pickers::Provider::TargetFileRequest{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI>
    {
        int32_t __stdcall AddFile(void* id, void* file, int32_t* addResult) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *addResult = detach_from<winrt::Windows::Storage::Pickers::Provider::AddFileResult>(this->shim().AddFile(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveFile(void* id) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveFile(*reinterpret_cast<hstring const*>(&id));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ContainsFile(void* id, bool* isContained) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isContained = detach_from<bool>(this->shim().ContainsFile(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CanAddFile(void* file, bool* canAdd) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *canAdd = detach_from<bool>(this->shim().CanAddFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedFileTypes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AllowedFileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::Provider::FileSelectionMode>(this->shim().SelectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SettingsIdentifier(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SettingsIdentifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FileRemoved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FileRemoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileOpenPickerUI, winrt::Windows::Storage::Pickers::Provider::FileRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FileRemoved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FileRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Closing(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closing(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileOpenPickerUI, winrt::Windows::Storage::Pickers::Provider::PickerClosingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closing(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closing(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::IFileRemovedEventArgs> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::IFileRemovedEventArgs>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI>
    {
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedFileTypes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AllowedFileTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SettingsIdentifier(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SettingsIdentifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetFileName(void* value, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Pickers::Provider::SetFileNameResult>(this->shim().TrySetFileName(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FileNameChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FileNameChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileSavePickerUI, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FileNameChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FileNameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TargetFileRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TargetFileRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Storage::Pickers::Provider::FileSavePickerUI, winrt::Windows::Storage::Pickers::Provider::TargetFileRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TargetFileRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetFileRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::IPickerClosingDeferral> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::IPickerClosingDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::IPickerClosingEventArgs> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::IPickerClosingEventArgs>
    {
        int32_t __stdcall get_ClosingOperation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::Provider::PickerClosingOperation>(this->shim().ClosingOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCanceled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCanceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::IPickerClosingOperation> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::IPickerClosingOperation>
    {
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::Provider::PickerClosingDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Deadline(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::ITargetFileRequest> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::ITargetFileRequest>
    {
        int32_t __stdcall get_TargetFile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::IStorageFile>(this->shim().TargetFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetFile(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::Provider::TargetFileRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestDeferral> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestedEventArgs> : produce_base<D, winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::Provider::TargetFileRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Storage::Pickers::Provider
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::IFileOpenPickerUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::IFileRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::IFileSavePickerUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::IPickerClosingDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::IPickerClosingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::IPickerClosingOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::ITargetFileRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::ITargetFileRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::FileOpenPickerUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::FileRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::FileSavePickerUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::PickerClosingDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::PickerClosingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::PickerClosingOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::TargetFileRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::TargetFileRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::Provider::TargetFileRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
