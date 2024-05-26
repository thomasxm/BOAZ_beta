// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Protection_2_H
#define WINRT_Windows_Media_Protection_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Media.Protection.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::Protection
{
    struct ComponentLoadFailedEventHandler : winrt::Windows::Foundation::IUnknown
    {
        ComponentLoadFailedEventHandler(std::nullptr_t = nullptr) noexcept {}
        ComponentLoadFailedEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> ComponentLoadFailedEventHandler(L lambda);
        template <typename F> ComponentLoadFailedEventHandler(F* function);
        template <typename O, typename M> ComponentLoadFailedEventHandler(O* object, M method);
        template <typename O, typename M> ComponentLoadFailedEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> ComponentLoadFailedEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Media::Protection::MediaProtectionManager const& sender, winrt::Windows::Media::Protection::ComponentLoadFailedEventArgs const& e) const;
    };
    struct RebootNeededEventHandler : winrt::Windows::Foundation::IUnknown
    {
        RebootNeededEventHandler(std::nullptr_t = nullptr) noexcept {}
        RebootNeededEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> RebootNeededEventHandler(L lambda);
        template <typename F> RebootNeededEventHandler(F* function);
        template <typename O, typename M> RebootNeededEventHandler(O* object, M method);
        template <typename O, typename M> RebootNeededEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> RebootNeededEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Media::Protection::MediaProtectionManager const& sender) const;
    };
    struct ServiceRequestedEventHandler : winrt::Windows::Foundation::IUnknown
    {
        ServiceRequestedEventHandler(std::nullptr_t = nullptr) noexcept {}
        ServiceRequestedEventHandler(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> ServiceRequestedEventHandler(L lambda);
        template <typename F> ServiceRequestedEventHandler(F* function);
        template <typename O, typename M> ServiceRequestedEventHandler(O* object, M method);
        template <typename O, typename M> ServiceRequestedEventHandler(com_ptr<O>&& object, M method);
        template <typename O, typename M> ServiceRequestedEventHandler(weak_ref<O>&& object, M method);
        auto operator()(winrt::Windows::Media::Protection::MediaProtectionManager const& sender, winrt::Windows::Media::Protection::ServiceRequestedEventArgs const& e) const;
    };
    struct __declspec(empty_bases) ComponentLoadFailedEventArgs : winrt::Windows::Media::Protection::IComponentLoadFailedEventArgs
    {
        ComponentLoadFailedEventArgs(std::nullptr_t) noexcept {}
        ComponentLoadFailedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IComponentLoadFailedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct ComponentRenewal
    {
        ComponentRenewal() = delete;
        static auto RenewSystemComponentsAsync(winrt::Windows::Media::Protection::RevocationAndRenewalInformation const& information);
    };
    struct __declspec(empty_bases) HdcpSession : winrt::Windows::Media::Protection::IHdcpSession
    {
        HdcpSession(std::nullptr_t) noexcept {}
        HdcpSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IHdcpSession(ptr, take_ownership_from_abi) {}
        HdcpSession();
    };
    struct __declspec(empty_bases) MediaProtectionManager : winrt::Windows::Media::Protection::IMediaProtectionManager
    {
        MediaProtectionManager(std::nullptr_t) noexcept {}
        MediaProtectionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IMediaProtectionManager(ptr, take_ownership_from_abi) {}
        MediaProtectionManager();
    };
    struct __declspec(empty_bases) MediaProtectionPMPServer : winrt::Windows::Media::Protection::IMediaProtectionPMPServer
    {
        MediaProtectionPMPServer(std::nullptr_t) noexcept {}
        MediaProtectionPMPServer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IMediaProtectionPMPServer(ptr, take_ownership_from_abi) {}
        explicit MediaProtectionPMPServer(winrt::Windows::Foundation::Collections::IPropertySet const& pProperties);
    };
    struct __declspec(empty_bases) MediaProtectionServiceCompletion : winrt::Windows::Media::Protection::IMediaProtectionServiceCompletion
    {
        MediaProtectionServiceCompletion(std::nullptr_t) noexcept {}
        MediaProtectionServiceCompletion(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IMediaProtectionServiceCompletion(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ProtectionCapabilities : winrt::Windows::Media::Protection::IProtectionCapabilities
    {
        ProtectionCapabilities(std::nullptr_t) noexcept {}
        ProtectionCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IProtectionCapabilities(ptr, take_ownership_from_abi) {}
        ProtectionCapabilities();
    };
    struct __declspec(empty_bases) RevocationAndRenewalInformation : winrt::Windows::Media::Protection::IRevocationAndRenewalInformation
    {
        RevocationAndRenewalInformation(std::nullptr_t) noexcept {}
        RevocationAndRenewalInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IRevocationAndRenewalInformation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RevocationAndRenewalItem : winrt::Windows::Media::Protection::IRevocationAndRenewalItem
    {
        RevocationAndRenewalItem(std::nullptr_t) noexcept {}
        RevocationAndRenewalItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IRevocationAndRenewalItem(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ServiceRequestedEventArgs : winrt::Windows::Media::Protection::IServiceRequestedEventArgs,
        impl::require<ServiceRequestedEventArgs, winrt::Windows::Media::Protection::IServiceRequestedEventArgs2>
    {
        ServiceRequestedEventArgs(std::nullptr_t) noexcept {}
        ServiceRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Protection::IServiceRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
