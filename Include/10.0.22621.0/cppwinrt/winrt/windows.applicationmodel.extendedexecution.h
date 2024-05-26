// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_ExtendedExecution_H
#define WINRT_Windows_ApplicationModel_ExtendedExecution_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionRevokedEventArgs<D>::Reason() const
    {
        winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Reason() const
    {
        winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Reason(winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->put_Reason(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Description(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->put_Description(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::PercentProgress() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->get_PercentProgress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::PercentProgress(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->put_PercentProgress(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->add_Revoked(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked_revoker consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Revoked_revoker>(this, Revoked(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->remove_Revoked(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult>) consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::RequestExtensionAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->RequestExtensionAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession> : produce_base<D, winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Reason(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reason(*reinterpret_cast<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason const*>(&value));
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
        int32_t __stdcall put_Description(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PercentProgress(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PercentProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PercentProgress(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PercentProgress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Revoked(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Revoked(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Revoked(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Revoked(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall RequestExtensionAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult>>(this->shim().RequestExtensionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution
{
    inline ExtendedExecutionSession::ExtendedExecutionSession() :
        ExtendedExecutionSession(impl::call_factory_cast<ExtendedExecutionSession(*)(winrt::Windows::Foundation::IActivationFactory const&), ExtendedExecutionSession>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ExtendedExecutionSession>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionSession> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
