// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Pickers_H
#define WINRT_Windows_Storage_Pickers_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Storage.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Storage.Pickers.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::PickerViewMode) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::ViewMode() const
    {
        winrt::Windows::Storage::Pickers::PickerViewMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->get_ViewMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::ViewMode(winrt::Windows::Storage::Pickers::PickerViewMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->put_ViewMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::SettingsIdentifier() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->get_SettingsIdentifier(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::SettingsIdentifier(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->put_SettingsIdentifier(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::PickerLocationId) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::SuggestedStartLocation() const
    {
        winrt::Windows::Storage::Pickers::PickerLocationId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->get_SuggestedStartLocation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::SuggestedStartLocation(winrt::Windows::Storage::Pickers::PickerLocationId const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->put_SuggestedStartLocation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::CommitButtonText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->get_CommitButtonText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::CommitButtonText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->put_CommitButtonText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::FileTypeFilter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->get_FileTypeFilter(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::PickSingleFileAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->PickSingleFileAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFile>>) consume_Windows_Storage_Pickers_IFileOpenPicker<D>::PickMultipleFilesAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker)->PickMultipleFilesAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFile>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Storage_Pickers_IFileOpenPicker2<D>::ContinuationData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker2)->get_ContinuationData(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileOpenPicker2<D>::PickSingleFileAndContinue() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker2)->PickSingleFileAndContinue());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileOpenPicker2<D>::PickMultipleFilesAndContinue() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker2)->PickMultipleFilesAndContinue());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_Storage_Pickers_IFileOpenPicker3<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPicker3)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_Pickers_IFileOpenPickerStatics<D>::ResumePickSingleFileAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPickerStatics)->ResumePickSingleFileAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::FileOpenPicker) consume_Windows_Storage_Pickers_IFileOpenPickerStatics2<D>::CreateForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPickerStatics2)->CreateForUser(*(void**)(&user), &result));
        return winrt::Windows::Storage::Pickers::FileOpenPicker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_Pickers_IFileOpenPickerWithOperationId<D>::PickSingleFileAsync(param::hstring const& pickerOperationId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileOpenPickerWithOperationId)->PickSingleFileAsync(*(void**)(&pickerOperationId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SettingsIdentifier() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->get_SettingsIdentifier(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SettingsIdentifier(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->put_SettingsIdentifier(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::PickerLocationId) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SuggestedStartLocation() const
    {
        winrt::Windows::Storage::Pickers::PickerLocationId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->get_SuggestedStartLocation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SuggestedStartLocation(winrt::Windows::Storage::Pickers::PickerLocationId const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->put_SuggestedStartLocation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFileSavePicker<D>::CommitButtonText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->get_CommitButtonText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker<D>::CommitButtonText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->put_CommitButtonText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Foundation::Collections::IVector<hstring>>) consume_Windows_Storage_Pickers_IFileSavePicker<D>::FileTypeChoices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->get_FileTypeChoices(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Foundation::Collections::IVector<hstring>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFileSavePicker<D>::DefaultFileExtension() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->get_DefaultFileExtension(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker<D>::DefaultFileExtension(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->put_DefaultFileExtension(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SuggestedSaveFile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->get_SuggestedSaveFile(&value));
        return winrt::Windows::Storage::StorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SuggestedSaveFile(winrt::Windows::Storage::StorageFile const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->put_SuggestedSaveFile(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SuggestedFileName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->get_SuggestedFileName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker<D>::SuggestedFileName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->put_SuggestedFileName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>) consume_Windows_Storage_Pickers_IFileSavePicker<D>::PickSaveFileAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker)->PickSaveFileAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Storage_Pickers_IFileSavePicker2<D>::ContinuationData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker2)->get_ContinuationData(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker2<D>::PickSaveFileAndContinue() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker2)->PickSaveFileAndContinue());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFileSavePicker3<D>::EnterpriseId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker3)->get_EnterpriseId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFileSavePicker3<D>::EnterpriseId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker3)->put_EnterpriseId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_Storage_Pickers_IFileSavePicker4<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePicker4)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::FileSavePicker) consume_Windows_Storage_Pickers_IFileSavePickerStatics<D>::CreateForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFileSavePickerStatics)->CreateForUser(*(void**)(&user), &result));
        return winrt::Windows::Storage::Pickers::FileSavePicker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::PickerViewMode) consume_Windows_Storage_Pickers_IFolderPicker<D>::ViewMode() const
    {
        winrt::Windows::Storage::Pickers::PickerViewMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->get_ViewMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFolderPicker<D>::ViewMode(winrt::Windows::Storage::Pickers::PickerViewMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->put_ViewMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFolderPicker<D>::SettingsIdentifier() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->get_SettingsIdentifier(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFolderPicker<D>::SettingsIdentifier(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->put_SettingsIdentifier(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::PickerLocationId) consume_Windows_Storage_Pickers_IFolderPicker<D>::SuggestedStartLocation() const
    {
        winrt::Windows::Storage::Pickers::PickerLocationId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->get_SuggestedStartLocation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFolderPicker<D>::SuggestedStartLocation(winrt::Windows::Storage::Pickers::PickerLocationId const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->put_SuggestedStartLocation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Pickers_IFolderPicker<D>::CommitButtonText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->get_CommitButtonText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFolderPicker<D>::CommitButtonText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->put_CommitButtonText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Storage_Pickers_IFolderPicker<D>::FileTypeFilter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->get_FileTypeFilter(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>) consume_Windows_Storage_Pickers_IFolderPicker<D>::PickSingleFolderAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker)->PickSingleFolderAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Storage_Pickers_IFolderPicker2<D>::ContinuationData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker2)->get_ContinuationData(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Pickers_IFolderPicker2<D>::PickFolderAndContinue() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker2)->PickFolderAndContinue());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_Storage_Pickers_IFolderPicker3<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPicker3)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Pickers::FolderPicker) consume_Windows_Storage_Pickers_IFolderPickerStatics<D>::CreateForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Pickers::IFolderPickerStatics)->CreateForUser(*(void**)(&user), &result));
        return winrt::Windows::Storage::Pickers::FolderPicker{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileOpenPicker> : produce_base<D, winrt::Windows::Storage::Pickers::IFileOpenPicker>
    {
        int32_t __stdcall get_ViewMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::PickerViewMode>(this->shim().ViewMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ViewMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ViewMode(*reinterpret_cast<winrt::Windows::Storage::Pickers::PickerViewMode const*>(&value));
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
        int32_t __stdcall put_SettingsIdentifier(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SettingsIdentifier(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuggestedStartLocation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::PickerLocationId>(this->shim().SuggestedStartLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuggestedStartLocation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestedStartLocation(*reinterpret_cast<winrt::Windows::Storage::Pickers::PickerLocationId const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommitButtonText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CommitButtonText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommitButtonText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommitButtonText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileTypeFilter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().FileTypeFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleFileAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().PickSingleFileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickMultipleFilesAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::StorageFile>>>(this->shim().PickMultipleFilesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileOpenPicker2> : produce_base<D, winrt::Windows::Storage::Pickers::IFileOpenPicker2>
    {
        int32_t __stdcall get_ContinuationData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().ContinuationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleFileAndContinue() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PickSingleFileAndContinue();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickMultipleFilesAndContinue() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PickMultipleFilesAndContinue();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileOpenPicker3> : produce_base<D, winrt::Windows::Storage::Pickers::IFileOpenPicker3>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileOpenPickerStatics> : produce_base<D, winrt::Windows::Storage::Pickers::IFileOpenPickerStatics>
    {
        int32_t __stdcall ResumePickSingleFileAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().ResumePickSingleFileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileOpenPickerStatics2> : produce_base<D, winrt::Windows::Storage::Pickers::IFileOpenPickerStatics2>
    {
        int32_t __stdcall CreateForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Pickers::FileOpenPicker>(this->shim().CreateForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileOpenPickerWithOperationId> : produce_base<D, winrt::Windows::Storage::Pickers::IFileOpenPickerWithOperationId>
    {
        int32_t __stdcall PickSingleFileAsync(void* pickerOperationId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().PickSingleFileAsync(*reinterpret_cast<hstring const*>(&pickerOperationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileSavePicker> : produce_base<D, winrt::Windows::Storage::Pickers::IFileSavePicker>
    {
        int32_t __stdcall get_SettingsIdentifier(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SettingsIdentifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SettingsIdentifier(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SettingsIdentifier(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuggestedStartLocation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::PickerLocationId>(this->shim().SuggestedStartLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuggestedStartLocation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestedStartLocation(*reinterpret_cast<winrt::Windows::Storage::Pickers::PickerLocationId const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommitButtonText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CommitButtonText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommitButtonText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommitButtonText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileTypeChoices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Foundation::Collections::IVector<hstring>>>(this->shim().FileTypeChoices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultFileExtension(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DefaultFileExtension());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultFileExtension(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultFileExtension(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuggestedSaveFile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFile>(this->shim().SuggestedSaveFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuggestedSaveFile(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestedSaveFile(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuggestedFileName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SuggestedFileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuggestedFileName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestedFileName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSaveFileAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>>(this->shim().PickSaveFileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileSavePicker2> : produce_base<D, winrt::Windows::Storage::Pickers::IFileSavePicker2>
    {
        int32_t __stdcall get_ContinuationData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().ContinuationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSaveFileAndContinue() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PickSaveFileAndContinue();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileSavePicker3> : produce_base<D, winrt::Windows::Storage::Pickers::IFileSavePicker3>
    {
        int32_t __stdcall get_EnterpriseId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EnterpriseId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnterpriseId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileSavePicker4> : produce_base<D, winrt::Windows::Storage::Pickers::IFileSavePicker4>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFileSavePickerStatics> : produce_base<D, winrt::Windows::Storage::Pickers::IFileSavePickerStatics>
    {
        int32_t __stdcall CreateForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Pickers::FileSavePicker>(this->shim().CreateForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFolderPicker> : produce_base<D, winrt::Windows::Storage::Pickers::IFolderPicker>
    {
        int32_t __stdcall get_ViewMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::PickerViewMode>(this->shim().ViewMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ViewMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ViewMode(*reinterpret_cast<winrt::Windows::Storage::Pickers::PickerViewMode const*>(&value));
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
        int32_t __stdcall put_SettingsIdentifier(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SettingsIdentifier(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SuggestedStartLocation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Pickers::PickerLocationId>(this->shim().SuggestedStartLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SuggestedStartLocation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestedStartLocation(*reinterpret_cast<winrt::Windows::Storage::Pickers::PickerLocationId const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommitButtonText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CommitButtonText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommitButtonText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommitButtonText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileTypeFilter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().FileTypeFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickSingleFolderAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFolder>>(this->shim().PickSingleFolderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFolderPicker2> : produce_base<D, winrt::Windows::Storage::Pickers::IFolderPicker2>
    {
        int32_t __stdcall get_ContinuationData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().ContinuationData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickFolderAndContinue() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PickFolderAndContinue();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFolderPicker3> : produce_base<D, winrt::Windows::Storage::Pickers::IFolderPicker3>
    {
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Pickers::IFolderPickerStatics> : produce_base<D, winrt::Windows::Storage::Pickers::IFolderPickerStatics>
    {
        int32_t __stdcall CreateForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Pickers::FolderPicker>(this->shim().CreateForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Storage::Pickers
{
    inline FileOpenPicker::FileOpenPicker() :
        FileOpenPicker(impl::call_factory_cast<FileOpenPicker(*)(winrt::Windows::Foundation::IActivationFactory const&), FileOpenPicker>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FileOpenPicker>(); }))
    {
    }
    inline auto FileOpenPicker::ResumePickSingleFileAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageFile>(*)(IFileOpenPickerStatics const&), FileOpenPicker, IFileOpenPickerStatics>([](IFileOpenPickerStatics const& f) { return f.ResumePickSingleFileAsync(); });
    }
    inline auto FileOpenPicker::CreateForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<FileOpenPicker, IFileOpenPickerStatics2>([&](IFileOpenPickerStatics2 const& f) { return f.CreateForUser(user); });
    }
    inline FileSavePicker::FileSavePicker() :
        FileSavePicker(impl::call_factory_cast<FileSavePicker(*)(winrt::Windows::Foundation::IActivationFactory const&), FileSavePicker>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FileSavePicker>(); }))
    {
    }
    inline auto FileSavePicker::CreateForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<FileSavePicker, IFileSavePickerStatics>([&](IFileSavePickerStatics const& f) { return f.CreateForUser(user); });
    }
    inline FolderPicker::FolderPicker() :
        FolderPicker(impl::call_factory_cast<FolderPicker(*)(winrt::Windows::Foundation::IActivationFactory const&), FolderPicker>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FolderPicker>(); }))
    {
    }
    inline auto FolderPicker::CreateForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<FolderPicker, IFolderPickerStatics>([&](IFolderPickerStatics const& f) { return f.CreateForUser(user); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileOpenPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileOpenPicker2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileOpenPicker3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileOpenPickerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileOpenPickerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileOpenPickerWithOperationId> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileSavePicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileSavePicker2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileSavePicker3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileSavePicker4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFileSavePickerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFolderPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFolderPicker2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFolderPicker3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::IFolderPickerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::FileExtensionVector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::FileOpenPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::FilePickerFileTypesOrderedMap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::FilePickerSelectedFilesArray> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::FileSavePicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Pickers::FolderPicker> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
