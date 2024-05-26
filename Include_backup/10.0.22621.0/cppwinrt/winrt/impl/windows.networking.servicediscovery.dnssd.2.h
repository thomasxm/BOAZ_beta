// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_ServiceDiscovery_Dnssd_2_H
#define WINRT_Windows_Networking_ServiceDiscovery_Dnssd_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Networking.1.h"
#include "winrt/impl/Windows.Networking.ServiceDiscovery.Dnssd.1.h"
WINRT_EXPORT namespace winrt::Windows::Networking::ServiceDiscovery::Dnssd
{
    struct __declspec(empty_bases) DnssdRegistrationResult : winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult,
        impl::require<DnssdRegistrationResult, winrt::Windows::Foundation::IStringable>
    {
        DnssdRegistrationResult(std::nullptr_t) noexcept {}
        DnssdRegistrationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult(ptr, take_ownership_from_abi) {}
        DnssdRegistrationResult();
    };
    struct __declspec(empty_bases) DnssdServiceInstance : winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance,
        impl::require<DnssdServiceInstance, winrt::Windows::Foundation::IStringable>
    {
        DnssdServiceInstance(std::nullptr_t) noexcept {}
        DnssdServiceInstance(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance(ptr, take_ownership_from_abi) {}
        DnssdServiceInstance(param::hstring const& dnssdServiceInstanceName, winrt::Windows::Networking::HostName const& hostName, uint16_t port);
    };
    struct __declspec(empty_bases) DnssdServiceInstanceCollection : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>
    {
        DnssdServiceInstanceCollection(std::nullptr_t) noexcept {}
        DnssdServiceInstanceCollection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DnssdServiceWatcher : winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher
    {
        DnssdServiceWatcher(std::nullptr_t) noexcept {}
        DnssdServiceWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher(ptr, take_ownership_from_abi) {}
    };
}
#endif
