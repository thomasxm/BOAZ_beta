// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authorization_AppCapabilityAccess_H
#define WINRT_Windows_Security_Authorization_AppCapabilityAccess_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.Authorization.AppCapabilityAccess.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::CapabilityName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->get_CapabilityName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::User() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->get_User(&value));
        return winrt::Windows::System::User{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::RequestAccessAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->RequestAccessAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::CheckAccess() const
    {
        winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->CheckAccess(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->add_AccessChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged_revoker consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccessChanged_revoker>(this, AccessChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->remove_AccessChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability2<D>::DisplayMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2)->get_DisplayMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability2<D>::DisplayMessage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2)->put_DisplayMessage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->RequestAccessForCapabilitiesAsync(*(void**)(&capabilityNames), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::RequestAccessForCapabilitiesForUserAsync(winrt::Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->RequestAccessForCapabilitiesForUserAsync(*(void**)(&user), *(void**)(&capabilityNames), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::Create(param::hstring const& capabilityName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->Create(*(void**)(&capabilityName), &result));
        return winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability) consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::CreateWithProcessIdForUser(winrt::Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->CreateWithProcessIdForUser(*(void**)(&user), *(void**)(&capabilityName), pid, &result));
        return winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability> : produce_base<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>
    {
        int32_t __stdcall get_CapabilityName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CapabilityName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_User(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CheckAccess(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>(this->shim().CheckAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AccessChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccessChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccessChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccessChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2> : produce_base<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2>
    {
        int32_t __stdcall get_DisplayMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayMessage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs> : produce_base<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics> : produce_base<D, winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>
    {
        int32_t __stdcall RequestAccessForCapabilitiesAsync(void* capabilityNames, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>>(this->shim().RequestAccessForCapabilitiesAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&capabilityNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestAccessForCapabilitiesForUserAsync(void* user, void* capabilityNames, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>>(this->shim().RequestAccessForCapabilitiesForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&capabilityNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Create(void* capabilityName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability>(this->shim().Create(*reinterpret_cast<hstring const*>(&capabilityName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithProcessIdForUser(void* user, void* capabilityName, uint32_t pid, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability>(this->shim().CreateWithProcessIdForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&capabilityName), pid));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess
{
    inline auto AppCapability::RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames)
    {
        return impl::call_factory<AppCapability, IAppCapabilityStatics>([&](IAppCapabilityStatics const& f) { return f.RequestAccessForCapabilitiesAsync(capabilityNames); });
    }
    inline auto AppCapability::RequestAccessForCapabilitiesForUserAsync(winrt::Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames)
    {
        return impl::call_factory<AppCapability, IAppCapabilityStatics>([&](IAppCapabilityStatics const& f) { return f.RequestAccessForCapabilitiesForUserAsync(user, capabilityNames); });
    }
    inline auto AppCapability::Create(param::hstring const& capabilityName)
    {
        return impl::call_factory<AppCapability, IAppCapabilityStatics>([&](IAppCapabilityStatics const& f) { return f.Create(capabilityName); });
    }
    inline auto AppCapability::CreateWithProcessIdForUser(winrt::Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid)
    {
        return impl::call_factory<AppCapability, IAppCapabilityStatics>([&](IAppCapabilityStatics const& f) { return f.CreateWithProcessIdForUser(user, capabilityName, pid); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
