// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Perception_Provider_1_H
#define WINRT_Windows_Devices_Perception_Provider_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Perception.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Perception::Provider
{
    struct __declspec(empty_bases) IKnownPerceptionFrameKindStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKnownPerceptionFrameKindStatics>
    {
        IKnownPerceptionFrameKindStatics(std::nullptr_t = nullptr) noexcept {}
        IKnownPerceptionFrameKindStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionControlGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionControlGroup>
    {
        IPerceptionControlGroup(std::nullptr_t = nullptr) noexcept {}
        IPerceptionControlGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionControlGroupFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionControlGroupFactory>
    {
        IPerceptionControlGroupFactory(std::nullptr_t = nullptr) noexcept {}
        IPerceptionControlGroupFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionCorrelation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionCorrelation>
    {
        IPerceptionCorrelation(std::nullptr_t = nullptr) noexcept {}
        IPerceptionCorrelation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionCorrelationFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionCorrelationFactory>
    {
        IPerceptionCorrelationFactory(std::nullptr_t = nullptr) noexcept {}
        IPerceptionCorrelationFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionCorrelationGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionCorrelationGroup>
    {
        IPerceptionCorrelationGroup(std::nullptr_t = nullptr) noexcept {}
        IPerceptionCorrelationGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionCorrelationGroupFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionCorrelationGroupFactory>
    {
        IPerceptionCorrelationGroupFactory(std::nullptr_t = nullptr) noexcept {}
        IPerceptionCorrelationGroupFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionFaceAuthenticationGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionFaceAuthenticationGroup>
    {
        IPerceptionFaceAuthenticationGroup(std::nullptr_t = nullptr) noexcept {}
        IPerceptionFaceAuthenticationGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionFaceAuthenticationGroupFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionFaceAuthenticationGroupFactory>
    {
        IPerceptionFaceAuthenticationGroupFactory(std::nullptr_t = nullptr) noexcept {}
        IPerceptionFaceAuthenticationGroupFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionFrame :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionFrame>
    {
        IPerceptionFrame(std::nullptr_t = nullptr) noexcept {}
        IPerceptionFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionFrameProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionFrameProvider>,
        impl::require<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider, winrt::Windows::Foundation::IClosable>
    {
        IPerceptionFrameProvider(std::nullptr_t = nullptr) noexcept {}
        IPerceptionFrameProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionFrameProviderInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionFrameProviderInfo>
    {
        IPerceptionFrameProviderInfo(std::nullptr_t = nullptr) noexcept {}
        IPerceptionFrameProviderInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionFrameProviderManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionFrameProviderManager>,
        impl::require<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager, winrt::Windows::Foundation::IClosable>
    {
        IPerceptionFrameProviderManager(std::nullptr_t = nullptr) noexcept {}
        IPerceptionFrameProviderManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionFrameProviderManagerServiceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionFrameProviderManagerServiceStatics>
    {
        IPerceptionFrameProviderManagerServiceStatics(std::nullptr_t = nullptr) noexcept {}
        IPerceptionFrameProviderManagerServiceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionPropertyChangeRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionPropertyChangeRequest>
    {
        IPerceptionPropertyChangeRequest(std::nullptr_t = nullptr) noexcept {}
        IPerceptionPropertyChangeRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionVideoFrameAllocator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionVideoFrameAllocator>,
        impl::require<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator, winrt::Windows::Foundation::IClosable>
    {
        IPerceptionVideoFrameAllocator(std::nullptr_t = nullptr) noexcept {}
        IPerceptionVideoFrameAllocator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerceptionVideoFrameAllocatorFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerceptionVideoFrameAllocatorFactory>
    {
        IPerceptionVideoFrameAllocatorFactory(std::nullptr_t = nullptr) noexcept {}
        IPerceptionVideoFrameAllocatorFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
