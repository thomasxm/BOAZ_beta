// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_ServiceDiscovery_Dnssd_H
#define WINRT_Windows_Networking_ServiceDiscovery_Dnssd_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Networking.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Networking.ServiceDiscovery.Dnssd.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult<D>::Status() const
    {
        winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult<D>::IPAddress() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult)->get_IPAddress(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult<D>::HasInstanceNameChanged() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult)->get_HasInstanceNameChanged(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::DnssdServiceInstanceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_DnssdServiceInstanceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::DnssdServiceInstanceName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_DnssdServiceInstanceName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::HostName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_HostName(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::HostName(winrt::Windows::Networking::HostName const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_HostName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Port() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_Port(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Port(uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_Port(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Priority() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_Priority(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Priority(uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_Priority(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Weight() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_Weight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Weight(uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_Weight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::TextAttributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_TextAttributes(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterStreamSocketListenerAsync(winrt::Windows::Networking::Sockets::StreamSocketListener const& socket) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterStreamSocketListenerAsync1(*(void**)(&socket), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterStreamSocketListenerAsync(winrt::Windows::Networking::Sockets::StreamSocketListener const& socket, winrt::Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterStreamSocketListenerAsync2(*(void**)(&socket), *(void**)(&adapter), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterDatagramSocketAsync(winrt::Windows::Networking::Sockets::DatagramSocket const& socket) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterDatagramSocketAsync1(*(void**)(&socket), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterDatagramSocketAsync(winrt::Windows::Networking::Sockets::DatagramSocket const& socket, winrt::Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterDatagramSocketAsync2(*(void**)(&socket), *(void**)(&adapter), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstanceFactory<D>::Create(param::hstring const& dnssdServiceInstanceName, winrt::Windows::Networking::HostName const& hostName, uint16_t port) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory)->Create(*(void**)(&dnssdServiceInstanceName), *(void**)(&hostName), port, &result));
        return winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->add_Added(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added_revoker consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const& handler) const
    {
        return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->remove_Added(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->add_EnumerationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted_revoker consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->remove_EnumerationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->add_Stopped(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped_revoker consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->remove_Stopped(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Status() const
    {
        winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->get_Status(reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->Stop());
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult> : produce_base<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IPAddress(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().IPAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasInstanceNameChanged(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasInstanceNameChanged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance> : produce_base<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance>
    {
        int32_t __stdcall get_DnssdServiceInstanceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DnssdServiceInstanceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DnssdServiceInstanceName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DnssdServiceInstanceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HostName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().HostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HostName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HostName(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Port(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Port());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Port(uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Port(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Priority(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Priority(uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Priority(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Weight(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Weight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Weight(uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Weight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextAttributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().TextAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterStreamSocketListenerAsync1(void* socket, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterStreamSocketListenerAsync(*reinterpret_cast<winrt::Windows::Networking::Sockets::StreamSocketListener const*>(&socket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterStreamSocketListenerAsync2(void* socket, void* adapter, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterStreamSocketListenerAsync(*reinterpret_cast<winrt::Windows::Networking::Sockets::StreamSocketListener const*>(&socket), *reinterpret_cast<winrt::Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterDatagramSocketAsync1(void* socket, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterDatagramSocketAsync(*reinterpret_cast<winrt::Windows::Networking::Sockets::DatagramSocket const*>(&socket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterDatagramSocketAsync2(void* socket, void* adapter, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterDatagramSocketAsync(*reinterpret_cast<winrt::Windows::Networking::Sockets::DatagramSocket const*>(&socket), *reinterpret_cast<winrt::Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory> : produce_base<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory>
    {
        int32_t __stdcall Create(void* dnssdServiceInstanceName, void* hostName, uint16_t port, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>(this->shim().Create(*reinterpret_cast<hstring const*>(&dnssdServiceInstanceName), *reinterpret_cast<winrt::Windows::Networking::HostName const*>(&hostName), port));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher> : produce_base<D, winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>
    {
        int32_t __stdcall add_Added(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Added(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnumerationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Stopped(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Stopped(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Status(int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Networking::ServiceDiscovery::Dnssd
{
    inline DnssdRegistrationResult::DnssdRegistrationResult() :
        DnssdRegistrationResult(impl::call_factory_cast<DnssdRegistrationResult(*)(winrt::Windows::Foundation::IActivationFactory const&), DnssdRegistrationResult>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DnssdRegistrationResult>(); }))
    {
    }
    inline DnssdServiceInstance::DnssdServiceInstance(param::hstring const& dnssdServiceInstanceName, winrt::Windows::Networking::HostName const& hostName, uint16_t port) :
        DnssdServiceInstance(impl::call_factory<DnssdServiceInstance, IDnssdServiceInstanceFactory>([&](IDnssdServiceInstanceFactory const& f) { return f.Create(dnssdServiceInstanceName, hostName, port); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstanceCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
    template<> struct formatter<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult, wchar_t> : formatter<winrt::Windows::Foundation::IStringable, wchar_t> {};
    template<> struct formatter<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance, wchar_t> : formatter<winrt::Windows::Foundation::IStringable, wchar_t> {};
#endif
}
#endif
