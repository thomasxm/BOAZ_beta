// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_Identity_Provider_2_H
#define WINRT_Windows_Security_Authentication_Identity_Provider_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Security.Authentication.Identity.Provider.1.h"
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity::Provider
{
    struct __declspec(empty_bases) SecondaryAuthenticationFactorAuthentication : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication
    {
        SecondaryAuthenticationFactorAuthentication(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorAuthentication(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthentication(ptr, take_ownership_from_abi) {}
        static auto ShowNotificationMessageAsync(param::hstring const& deviceName, winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationMessage const& message);
        static auto StartAuthenticationAsync(param::hstring const& deviceId, winrt::Windows::Storage::Streams::IBuffer const& serviceAuthenticationNonce);
        static auto AuthenticationStageChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const& handler);
        using AuthenticationStageChanged_revoker = impl::factory_event_revoker<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics, &impl::abi_t<winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStatics>::remove_AuthenticationStageChanged>;
        [[nodiscard]] static AuthenticationStageChanged_revoker AuthenticationStageChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs> const& handler);
        static auto AuthenticationStageChanged(winrt::event_token const& token);
        static auto GetAuthenticationStageInfoAsync();
    };
    struct __declspec(empty_bases) SecondaryAuthenticationFactorAuthenticationResult : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult
    {
        SecondaryAuthenticationFactorAuthenticationResult(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorAuthenticationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs
    {
        SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorAuthenticationStageChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SecondaryAuthenticationFactorAuthenticationStageInfo : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo
    {
        SecondaryAuthenticationFactorAuthenticationStageInfo(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorAuthenticationStageInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorAuthenticationStageInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SecondaryAuthenticationFactorInfo : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo,
        impl::require<SecondaryAuthenticationFactorInfo, winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo2>
    {
        SecondaryAuthenticationFactorInfo(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorInfo(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SecondaryAuthenticationFactorRegistration : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration
    {
        SecondaryAuthenticationFactorRegistration(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorRegistration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistration(ptr, take_ownership_from_abi) {}
        static auto RegisterDevicePresenceMonitoringAsync(param::hstring const& deviceId, param::hstring const& deviceInstancePath, winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const& monitoringMode);
        static auto RegisterDevicePresenceMonitoringAsync(param::hstring const& deviceId, param::hstring const& deviceInstancePath, winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDevicePresenceMonitoringMode const& monitoringMode, param::hstring const& deviceFriendlyName, param::hstring const& deviceModelNumber, winrt::Windows::Storage::Streams::IBuffer const& deviceConfigurationData);
        static auto UnregisterDevicePresenceMonitoringAsync(param::hstring const& deviceId);
        static auto IsDevicePresenceMonitoringSupported();
        static auto RequestStartRegisteringDeviceAsync(param::hstring const& deviceId, winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceCapabilities const& capabilities, param::hstring const& deviceFriendlyName, param::hstring const& deviceModelNumber, winrt::Windows::Storage::Streams::IBuffer const& deviceKey, winrt::Windows::Storage::Streams::IBuffer const& mutualAuthenticationKey);
        static auto FindAllRegisteredDeviceInfoAsync(winrt::Windows::Security::Authentication::Identity::Provider::SecondaryAuthenticationFactorDeviceFindScope const& queryType);
        static auto UnregisterDeviceAsync(param::hstring const& deviceId);
        static auto UpdateDeviceConfigurationDataAsync(param::hstring const& deviceId, winrt::Windows::Storage::Streams::IBuffer const& deviceConfigurationData);
    };
    struct __declspec(empty_bases) SecondaryAuthenticationFactorRegistrationResult : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult
    {
        SecondaryAuthenticationFactorRegistrationResult(std::nullptr_t) noexcept {}
        SecondaryAuthenticationFactorRegistrationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Authentication::Identity::Provider::ISecondaryAuthenticationFactorRegistrationResult(ptr, take_ownership_from_abi) {}
    };
}
#endif
