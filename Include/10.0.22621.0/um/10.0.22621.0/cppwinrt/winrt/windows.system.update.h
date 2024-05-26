// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Update_H
#define WINRT_Windows_System_Update_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.Update.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateItemState) consume_Windows_System_Update_ISystemUpdateItem<D>::State() const
    {
        winrt::Windows::System::Update::SystemUpdateItemState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Update_ISystemUpdateItem<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Update_ISystemUpdateItem<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Update_ISystemUpdateItem<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Update_ISystemUpdateItem<D>::Revision() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_Revision(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_System_Update_ISystemUpdateItem<D>::DownloadProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_DownloadProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_System_Update_ISystemUpdateItem<D>::InstallProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_InstallProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_System_Update_ISystemUpdateItem<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateItem)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateManagerState) consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>::State() const
    {
        winrt::Windows::System::Update::SystemUpdateManagerState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateLastErrorInfo)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateLastErrorInfo)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>::IsInteractive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateLastErrorInfo)->get_IsInteractive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::IsSupported() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->IsSupported(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateManagerState) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::State() const
    {
        winrt::Windows::System::Update::SystemUpdateManagerState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->add_StateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged_revoker consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->remove_StateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::DownloadProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_DownloadProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::InstallProgress() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_InstallProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UserActiveHoursStart() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_UserActiveHoursStart(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UserActiveHoursEnd() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_UserActiveHoursEnd(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UserActiveHoursMax() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_UserActiveHoursMax(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::TrySetUserActiveHours(winrt::Windows::Foundation::TimeSpan const& start, winrt::Windows::Foundation::TimeSpan const& end) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->TrySetUserActiveHours(impl::bind_in(start), impl::bind_in(end), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::LastUpdateCheckTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_LastUpdateCheckTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::LastUpdateInstallTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_LastUpdateInstallTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateLastErrorInfo) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::LastErrorInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_LastErrorInfo(&value));
        return winrt::Windows::System::Update::SystemUpdateLastErrorInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::GetAutomaticRebootBlockIds() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->GetAutomaticRebootBlockIds(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::BlockAutomaticRebootAsync(param::hstring const& lockId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->BlockAutomaticRebootAsync(*(void**)(&lockId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::UnblockAutomaticRebootAsync(param::hstring const& lockId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->UnblockAutomaticRebootAsync(*(void**)(&lockId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Update::SystemUpdateItem>) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::GetUpdateItems() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->GetUpdateItems(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Update::SystemUpdateItem>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateAttentionRequiredReason) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::AttentionRequiredReason() const
    {
        winrt::Windows::System::Update::SystemUpdateAttentionRequiredReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->get_AttentionRequiredReason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::SetFlightRing(param::hstring const& flightRing) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->SetFlightRing(*(void**)(&flightRing), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::GetFlightRing() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->GetFlightRing(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StartInstall(winrt::Windows::System::Update::SystemUpdateStartInstallAction const& action) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->StartInstall(static_cast<int32_t>(action)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::RebootToCompleteInstall() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->RebootToCompleteInstall());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Update_ISystemUpdateManagerStatics<D>::StartCancelUpdates() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Update::ISystemUpdateManagerStatics)->StartCancelUpdates());
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Update::ISystemUpdateItem> : produce_base<D, winrt::Windows::System::Update::ISystemUpdateItem>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Update::SystemUpdateItemState>(this->shim().State());
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
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Revision(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Revision());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DownloadProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstallProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().InstallProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Update::ISystemUpdateLastErrorInfo> : produce_base<D, winrt::Windows::System::Update::ISystemUpdateLastErrorInfo>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Update::SystemUpdateManagerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInteractive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInteractive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Update::ISystemUpdateManagerStatics> : produce_base<D, winrt::Windows::System::Update::ISystemUpdateManagerStatics>
    {
        int32_t __stdcall IsSupported(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Update::SystemUpdateManagerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_DownloadProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstallProgress(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().InstallProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserActiveHoursStart(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().UserActiveHoursStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserActiveHoursEnd(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().UserActiveHoursEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserActiveHoursMax(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().UserActiveHoursMax());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TrySetUserActiveHours(int64_t start, int64_t end, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TrySetUserActiveHours(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&start), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&end)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastUpdateCheckTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastUpdateCheckTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastUpdateInstallTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastUpdateInstallTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastErrorInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Update::SystemUpdateLastErrorInfo>(this->shim().LastErrorInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAutomaticRebootBlockIds(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetAutomaticRebootBlockIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall BlockAutomaticRebootAsync(void* lockId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().BlockAutomaticRebootAsync(*reinterpret_cast<hstring const*>(&lockId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnblockAutomaticRebootAsync(void* lockId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().UnblockAutomaticRebootAsync(*reinterpret_cast<hstring const*>(&lockId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUpdateItems(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Update::SystemUpdateItem>>(this->shim().GetUpdateItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AttentionRequiredReason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Update::SystemUpdateAttentionRequiredReason>(this->shim().AttentionRequiredReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFlightRing(void* flightRing, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().SetFlightRing(*reinterpret_cast<hstring const*>(&flightRing)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFlightRing(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetFlightRing());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartInstall(int32_t action) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartInstall(*reinterpret_cast<winrt::Windows::System::Update::SystemUpdateStartInstallAction const*>(&action));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RebootToCompleteInstall() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RebootToCompleteInstall();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartCancelUpdates() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartCancelUpdates();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Update
{
    inline auto SystemUpdateManager::IsSupported()
    {
        return impl::call_factory_cast<bool(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.IsSupported(); });
    }
    inline auto SystemUpdateManager::State()
    {
        return impl::call_factory_cast<winrt::Windows::System::Update::SystemUpdateManagerState(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.State(); });
    }
    inline auto SystemUpdateManager::StateChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<SystemUpdateManager, ISystemUpdateManagerStatics>([&](ISystemUpdateManagerStatics const& f) { return f.StateChanged(handler); });
    }
    inline SystemUpdateManager::StateChanged_revoker SystemUpdateManager::StateChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<SystemUpdateManager, winrt::Windows::System::Update::ISystemUpdateManagerStatics>();
        return { f, f.StateChanged(handler) };
    }
    inline auto SystemUpdateManager::StateChanged(winrt::event_token const& token)
    {
        impl::call_factory<SystemUpdateManager, ISystemUpdateManagerStatics>([&](ISystemUpdateManagerStatics const& f) { return f.StateChanged(token); });
    }
    inline auto SystemUpdateManager::DownloadProgress()
    {
        return impl::call_factory_cast<double(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.DownloadProgress(); });
    }
    inline auto SystemUpdateManager::InstallProgress()
    {
        return impl::call_factory_cast<double(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.InstallProgress(); });
    }
    inline auto SystemUpdateManager::UserActiveHoursStart()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::TimeSpan(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.UserActiveHoursStart(); });
    }
    inline auto SystemUpdateManager::UserActiveHoursEnd()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::TimeSpan(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.UserActiveHoursEnd(); });
    }
    inline auto SystemUpdateManager::UserActiveHoursMax()
    {
        return impl::call_factory_cast<int32_t(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.UserActiveHoursMax(); });
    }
    inline auto SystemUpdateManager::TrySetUserActiveHours(winrt::Windows::Foundation::TimeSpan const& start, winrt::Windows::Foundation::TimeSpan const& end)
    {
        return impl::call_factory<SystemUpdateManager, ISystemUpdateManagerStatics>([&](ISystemUpdateManagerStatics const& f) { return f.TrySetUserActiveHours(start, end); });
    }
    inline auto SystemUpdateManager::LastUpdateCheckTime()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::DateTime(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.LastUpdateCheckTime(); });
    }
    inline auto SystemUpdateManager::LastUpdateInstallTime()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::DateTime(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.LastUpdateInstallTime(); });
    }
    inline auto SystemUpdateManager::LastErrorInfo()
    {
        return impl::call_factory_cast<winrt::Windows::System::Update::SystemUpdateLastErrorInfo(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.LastErrorInfo(); });
    }
    inline auto SystemUpdateManager::GetAutomaticRebootBlockIds()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring>(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.GetAutomaticRebootBlockIds(); });
    }
    inline auto SystemUpdateManager::BlockAutomaticRebootAsync(param::hstring const& lockId)
    {
        return impl::call_factory<SystemUpdateManager, ISystemUpdateManagerStatics>([&](ISystemUpdateManagerStatics const& f) { return f.BlockAutomaticRebootAsync(lockId); });
    }
    inline auto SystemUpdateManager::UnblockAutomaticRebootAsync(param::hstring const& lockId)
    {
        return impl::call_factory<SystemUpdateManager, ISystemUpdateManagerStatics>([&](ISystemUpdateManagerStatics const& f) { return f.UnblockAutomaticRebootAsync(lockId); });
    }
    inline auto SystemUpdateManager::ExtendedError()
    {
        return impl::call_factory_cast<winrt::hresult(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.ExtendedError(); });
    }
    inline auto SystemUpdateManager::GetUpdateItems()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Update::SystemUpdateItem>(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.GetUpdateItems(); });
    }
    inline auto SystemUpdateManager::AttentionRequiredReason()
    {
        return impl::call_factory_cast<winrt::Windows::System::Update::SystemUpdateAttentionRequiredReason(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.AttentionRequiredReason(); });
    }
    inline auto SystemUpdateManager::SetFlightRing(param::hstring const& flightRing)
    {
        return impl::call_factory<SystemUpdateManager, ISystemUpdateManagerStatics>([&](ISystemUpdateManagerStatics const& f) { return f.SetFlightRing(flightRing); });
    }
    inline auto SystemUpdateManager::GetFlightRing()
    {
        return impl::call_factory_cast<hstring(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.GetFlightRing(); });
    }
    inline auto SystemUpdateManager::StartInstall(winrt::Windows::System::Update::SystemUpdateStartInstallAction const& action)
    {
        impl::call_factory<SystemUpdateManager, ISystemUpdateManagerStatics>([&](ISystemUpdateManagerStatics const& f) { return f.StartInstall(action); });
    }
    inline auto SystemUpdateManager::RebootToCompleteInstall()
    {
        impl::call_factory_cast<void(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.RebootToCompleteInstall(); });
    }
    inline auto SystemUpdateManager::StartCancelUpdates()
    {
        impl::call_factory_cast<void(*)(ISystemUpdateManagerStatics const&), SystemUpdateManager, ISystemUpdateManagerStatics>([](ISystemUpdateManagerStatics const& f) { return f.StartCancelUpdates(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Update::ISystemUpdateItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Update::ISystemUpdateManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Update::SystemUpdateItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Update::SystemUpdateLastErrorInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Update::SystemUpdateManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
