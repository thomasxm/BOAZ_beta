// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Diagnostics_Telemetry_2_H
#define WINRT_Windows_System_Diagnostics_Telemetry_2_H
#include "winrt/impl/Windows.System.Diagnostics.Telemetry.1.h"
WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::Telemetry
{
    struct PlatformTelemetryClient
    {
        PlatformTelemetryClient() = delete;
        static auto Register(param::hstring const& id);
        static auto Register(param::hstring const& id, winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const& settings);
    };
    struct __declspec(empty_bases) PlatformTelemetryRegistrationResult : winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult
    {
        PlatformTelemetryRegistrationResult(std::nullptr_t) noexcept {}
        PlatformTelemetryRegistrationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PlatformTelemetryRegistrationSettings : winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings
    {
        PlatformTelemetryRegistrationSettings(std::nullptr_t) noexcept {}
        PlatformTelemetryRegistrationSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings(ptr, take_ownership_from_abi) {}
        PlatformTelemetryRegistrationSettings();
    };
}
#endif
