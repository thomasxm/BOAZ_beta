// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_DataProtection_H
#define WINRT_Windows_Security_DataProtection_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.DataProtection.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Security_DataProtection_IUserDataAvailabilityStateChangedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::DataProtection::UserDataBufferUnprotectStatus) consume_Windows_Security_DataProtection_IUserDataBufferUnprotectResult<D>::Status() const
    {
        winrt::Windows::Security::DataProtection::UserDataBufferUnprotectStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_DataProtection_IUserDataBufferUnprotectResult<D>::UnprotectedBuffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult)->get_UnprotectedBuffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>) consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::ProtectStorageItemAsync(winrt::Windows::Storage::IStorageItem const& storageItem, winrt::Windows::Security::DataProtection::UserDataAvailability const& availability) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManager)->ProtectStorageItemAsync(*(void**)(&storageItem), static_cast<int32_t>(availability), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo>) consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::GetStorageItemProtectionInfoAsync(winrt::Windows::Storage::IStorageItem const& storageItem) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManager)->GetStorageItemProtectionInfoAsync(*(void**)(&storageItem), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::ProtectBufferAsync(winrt::Windows::Storage::Streams::IBuffer const& unprotectedBuffer, winrt::Windows::Security::DataProtection::UserDataAvailability const& availability) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManager)->ProtectBufferAsync(*(void**)(&unprotectedBuffer), static_cast<int32_t>(availability), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataBufferUnprotectResult>) consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::UnprotectBufferAsync(winrt::Windows::Storage::Streams::IBuffer const& protectedBuffer) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManager)->UnprotectBufferAsync(*(void**)(&protectedBuffer), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataBufferUnprotectResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::IsContinuedDataAvailabilityExpected(winrt::Windows::Security::DataProtection::UserDataAvailability const& availability) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManager)->IsContinuedDataAvailabilityExpected(static_cast<int32_t>(availability), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::DataProtection::UserDataProtectionManager, winrt::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManager)->add_DataAvailabilityStateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged_revoker consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::DataProtection::UserDataProtectionManager, winrt::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DataAvailabilityStateChanged_revoker>(this, DataAvailabilityStateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_DataProtection_IUserDataProtectionManager<D>::DataAvailabilityStateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManager)->remove_DataAvailabilityStateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::DataProtection::UserDataProtectionManager) consume_Windows_Security_DataProtection_IUserDataProtectionManagerStatics<D>::TryGetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManagerStatics)->TryGetDefault(&result));
        return winrt::Windows::Security::DataProtection::UserDataProtectionManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::DataProtection::UserDataProtectionManager) consume_Windows_Security_DataProtection_IUserDataProtectionManagerStatics<D>::TryGetForUser(winrt::Windows::System::User const& user) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataProtectionManagerStatics)->TryGetForUser(*(void**)(&user), &result));
        return winrt::Windows::Security::DataProtection::UserDataProtectionManager{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::DataProtection::UserDataAvailability) consume_Windows_Security_DataProtection_IUserDataStorageItemProtectionInfo<D>::Availability() const
    {
        winrt::Windows::Security::DataProtection::UserDataAvailability value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo)->get_Availability(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs> : produce_base<D, winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs>
    {
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult> : produce_base<D, winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::DataProtection::UserDataBufferUnprotectStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnprotectedBuffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().UnprotectedBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::DataProtection::IUserDataProtectionManager> : produce_base<D, winrt::Windows::Security::DataProtection::IUserDataProtectionManager>
    {
        int32_t __stdcall ProtectStorageItemAsync(void* storageItem, int32_t availability, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionStatus>>(this->shim().ProtectStorageItemAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageItem const*>(&storageItem), *reinterpret_cast<winrt::Windows::Security::DataProtection::UserDataAvailability const*>(&availability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStorageItemProtectionInfoAsync(void* storageItem, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo>>(this->shim().GetStorageItemProtectionInfoAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageItem const*>(&storageItem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProtectBufferAsync(void* unprotectedBuffer, int32_t availability, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().ProtectBufferAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&unprotectedBuffer), *reinterpret_cast<winrt::Windows::Security::DataProtection::UserDataAvailability const*>(&availability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnprotectBufferAsync(void* protectedBuffer, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::DataProtection::UserDataBufferUnprotectResult>>(this->shim().UnprotectBufferAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&protectedBuffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsContinuedDataAvailabilityExpected(int32_t availability, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsContinuedDataAvailabilityExpected(*reinterpret_cast<winrt::Windows::Security::DataProtection::UserDataAvailability const*>(&availability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DataAvailabilityStateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DataAvailabilityStateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::DataProtection::UserDataProtectionManager, winrt::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DataAvailabilityStateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DataAvailabilityStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::DataProtection::IUserDataProtectionManagerStatics> : produce_base<D, winrt::Windows::Security::DataProtection::IUserDataProtectionManagerStatics>
    {
        int32_t __stdcall TryGetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::DataProtection::UserDataProtectionManager>(this->shim().TryGetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryGetForUser(void* user, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::DataProtection::UserDataProtectionManager>(this->shim().TryGetForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo> : produce_base<D, winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo>
    {
        int32_t __stdcall get_Availability(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::DataProtection::UserDataAvailability>(this->shim().Availability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Security::DataProtection
{
    inline auto UserDataProtectionManager::TryGetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Security::DataProtection::UserDataProtectionManager(*)(IUserDataProtectionManagerStatics const&), UserDataProtectionManager, IUserDataProtectionManagerStatics>([](IUserDataProtectionManagerStatics const& f) { return f.TryGetDefault(); });
    }
    inline auto UserDataProtectionManager::TryGetForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<UserDataProtectionManager, IUserDataProtectionManagerStatics>([&](IUserDataProtectionManagerStatics const& f) { return f.TryGetForUser(user); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataBufferUnprotectResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataProtectionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataProtectionManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::UserDataAvailabilityStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::UserDataBufferUnprotectResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::UserDataProtectionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::DataProtection::UserDataStorageItemProtectionInfo> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
