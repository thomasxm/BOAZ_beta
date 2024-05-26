// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_Identity_Provider_1_H
#define WINRT_Windows_Security_Authentication_Identity_Provider_1_H
#include "winrt/impl/Windows.Security.Authentication.Identity.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity::Provider
{
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorAuthentication :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorAuthentication>
    {
        ISecondaryAuthenticationFactorAuthentication(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorAuthentication(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorAuthenticationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorAuthenticationResult>
    {
        ISecondaryAuthenticationFactorAuthenticationResult(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorAuthenticationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs>
    {
        ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorAuthenticationStageInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorAuthenticationStageInfo>
    {
        ISecondaryAuthenticationFactorAuthenticationStageInfo(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorAuthenticationStageInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorAuthenticationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorAuthenticationStatics>
    {
        ISecondaryAuthenticationFactorAuthenticationStatics(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorAuthenticationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics>
    {
        ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorDevicePresenceMonitoringRegistrationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorInfo>
    {
        ISecondaryAuthenticationFactorInfo(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorInfo2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorInfo2>,
        impl::require<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2, winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo>
    {
        ISecondaryAuthenticationFactorInfo2(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorInfo2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorRegistration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorRegistration>
    {
        ISecondaryAuthenticationFactorRegistration(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorRegistration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorRegistrationResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorRegistrationResult>
    {
        ISecondaryAuthenticationFactorRegistrationResult(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorRegistrationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISecondaryAuthenticationFactorRegistrationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISecondaryAuthenticationFactorRegistrationStatics>
    {
        ISecondaryAuthenticationFactorRegistrationStatics(std::nullptr_t = nullptr) noexcept {}
        ISecondaryAuthenticationFactorRegistrationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
