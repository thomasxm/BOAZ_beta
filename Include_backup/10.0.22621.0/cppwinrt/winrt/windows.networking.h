// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_H
#define WINRT_Windows_Networking_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Networking.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_IEndpointPair<D>::LocalHostName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->get_LocalHostName(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_IEndpointPair<D>::LocalHostName(winrt::Windows::Networking::HostName const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->put_LocalHostName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_IEndpointPair<D>::LocalServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->get_LocalServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_IEndpointPair<D>::LocalServiceName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->put_LocalServiceName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_IEndpointPair<D>::RemoteHostName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->get_RemoteHostName(&value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_IEndpointPair<D>::RemoteHostName(winrt::Windows::Networking::HostName const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->put_RemoteHostName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_IEndpointPair<D>::RemoteServiceName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->get_RemoteServiceName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Networking_IEndpointPair<D>::RemoteServiceName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPair)->put_RemoteServiceName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::EndpointPair) consume_Windows_Networking_IEndpointPairFactory<D>::CreateEndpointPair(winrt::Windows::Networking::HostName const& localHostName, param::hstring const& localServiceName, winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IEndpointPairFactory)->CreateEndpointPair(*(void**)(&localHostName), *(void**)(&localServiceName), *(void**)(&remoteHostName), *(void**)(&remoteServiceName), &value));
        return winrt::Windows::Networking::EndpointPair{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::Connectivity::IPInformation) consume_Windows_Networking_IHostName<D>::IPInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostName)->get_IPInformation(&value));
        return winrt::Windows::Networking::Connectivity::IPInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_IHostName<D>::RawName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostName)->get_RawName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_IHostName<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostName)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Networking_IHostName<D>::CanonicalName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostName)->get_CanonicalName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostNameType) consume_Windows_Networking_IHostName<D>::Type() const
    {
        winrt::Windows::Networking::HostNameType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostName)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Networking_IHostName<D>::IsEqual(winrt::Windows::Networking::HostName const& hostName) const
    {
        bool isEqual{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostName)->IsEqual(*(void**)(&hostName), &isEqual));
        return isEqual;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) consume_Windows_Networking_IHostNameFactory<D>::CreateHostName(param::hstring const& hostName) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostNameFactory)->CreateHostName(*(void**)(&hostName), &value));
        return winrt::Windows::Networking::HostName{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Networking_IHostNameStatics<D>::Compare(param::hstring const& value1, param::hstring const& value2) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Networking::IHostNameStatics)->Compare(*(void**)(&value1), *(void**)(&value2), &result));
        return result;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::IEndpointPair> : produce_base<D, winrt::Windows::Networking::IEndpointPair>
    {
        int32_t __stdcall get_LocalHostName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().LocalHostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LocalHostName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LocalHostName(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LocalServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LocalServiceName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LocalServiceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteHostName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().RemoteHostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteHostName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteHostName(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteServiceName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoteServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RemoteServiceName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoteServiceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::IEndpointPairFactory> : produce_base<D, winrt::Windows::Networking::IEndpointPairFactory>
    {
        int32_t __stdcall CreateEndpointPair(void* localHostName, void* localServiceName, void* remoteHostName, void* remoteServiceName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::EndpointPair>(this->shim().CreateEndpointPair(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&localHostName), *reinterpret_cast<hstring const*>(&localServiceName), *reinterpret_cast<winrt::Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::IHostName> : produce_base<D, winrt::Windows::Networking::IHostName>
    {
        int32_t __stdcall get_IPInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::Connectivity::IPInformation>(this->shim().IPInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RawName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RawName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanonicalName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CanonicalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostNameType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsEqual(void* hostName, bool* isEqual) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isEqual = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<winrt::Windows::Networking::HostName const*>(&hostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::IHostNameFactory> : produce_base<D, winrt::Windows::Networking::IHostNameFactory>
    {
        int32_t __stdcall CreateHostName(void* hostName, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::HostName>(this->shim().CreateHostName(*reinterpret_cast<hstring const*>(&hostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Networking::IHostNameStatics> : produce_base<D, winrt::Windows::Networking::IHostNameStatics>
    {
        int32_t __stdcall Compare(void* value1, void* value2, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().Compare(*reinterpret_cast<hstring const*>(&value1), *reinterpret_cast<hstring const*>(&value2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Networking
{
    constexpr auto operator|(HostNameSortOptions const left, HostNameSortOptions const right) noexcept
    {
        return static_cast<HostNameSortOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(HostNameSortOptions& left, HostNameSortOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(HostNameSortOptions const left, HostNameSortOptions const right) noexcept
    {
        return static_cast<HostNameSortOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(HostNameSortOptions& left, HostNameSortOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(HostNameSortOptions const value) noexcept
    {
        return static_cast<HostNameSortOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(HostNameSortOptions const left, HostNameSortOptions const right) noexcept
    {
        return static_cast<HostNameSortOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(HostNameSortOptions& left, HostNameSortOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline EndpointPair::EndpointPair(winrt::Windows::Networking::HostName const& localHostName, param::hstring const& localServiceName, winrt::Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) :
        EndpointPair(impl::call_factory<EndpointPair, IEndpointPairFactory>([&](IEndpointPairFactory const& f) { return f.CreateEndpointPair(localHostName, localServiceName, remoteHostName, remoteServiceName); }))
    {
    }
    inline HostName::HostName(param::hstring const& hostName) :
        HostName(impl::call_factory<HostName, IHostNameFactory>([&](IHostNameFactory const& f) { return f.CreateHostName(hostName); }))
    {
    }
    inline auto HostName::Compare(param::hstring const& value1, param::hstring const& value2)
    {
        return impl::call_factory<HostName, IHostNameStatics>([&](IHostNameStatics const& f) { return f.Compare(value1, value2); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Networking::IEndpointPair> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::IEndpointPairFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::IHostName> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::IHostNameFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::IHostNameStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::EndpointPair> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Networking::HostName> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
    template<> struct formatter<winrt::Windows::Networking::HostName, wchar_t> : formatter<winrt::Windows::Foundation::IStringable, wchar_t> {};
#endif
}
#endif
