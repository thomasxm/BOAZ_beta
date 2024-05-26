// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Haptics_2_H
#define WINRT_Windows_Devices_Haptics_2_H
#include "winrt/impl/Windows.Devices.Haptics.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Haptics
{
    struct KnownSimpleHapticsControllerWaveforms
    {
        KnownSimpleHapticsControllerWaveforms() = delete;
        [[nodiscard]] static auto Click();
        [[nodiscard]] static auto BuzzContinuous();
        [[nodiscard]] static auto RumbleContinuous();
        [[nodiscard]] static auto Press();
        [[nodiscard]] static auto Release();
        [[nodiscard]] static auto BrushContinuous();
        [[nodiscard]] static auto ChiselMarkerContinuous();
        [[nodiscard]] static auto EraserContinuous();
        [[nodiscard]] static auto Error();
        [[nodiscard]] static auto GalaxyPenContinuous();
        [[nodiscard]] static auto Hover();
        [[nodiscard]] static auto InkContinuous();
        [[nodiscard]] static auto MarkerContinuous();
        [[nodiscard]] static auto PencilContinuous();
        [[nodiscard]] static auto Success();
    };
    struct __declspec(empty_bases) SimpleHapticsController : winrt::Windows::Devices::Haptics::ISimpleHapticsController
    {
        SimpleHapticsController(std::nullptr_t) noexcept {}
        SimpleHapticsController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Haptics::ISimpleHapticsController(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SimpleHapticsControllerFeedback : winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback
    {
        SimpleHapticsControllerFeedback(std::nullptr_t) noexcept {}
        SimpleHapticsControllerFeedback(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VibrationDevice : winrt::Windows::Devices::Haptics::IVibrationDevice
    {
        VibrationDevice(std::nullptr_t) noexcept {}
        VibrationDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Haptics::IVibrationDevice(ptr, take_ownership_from_abi) {}
        static auto RequestAccessAsync();
        static auto GetDeviceSelector();
        static auto FromIdAsync(param::hstring const& deviceId);
        static auto GetDefaultAsync();
        static auto FindAllAsync();
    };
}
#endif
