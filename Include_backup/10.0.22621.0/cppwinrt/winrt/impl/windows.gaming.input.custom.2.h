// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Gaming_Input_Custom_2_H
#define WINRT_Windows_Gaming_Input_Custom_2_H
#include "winrt/impl/Windows.Gaming.Input.1.h"
#include "winrt/impl/Windows.Gaming.Input.Custom.1.h"
WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Custom
{
    struct GameControllerVersionInfo
    {
        uint16_t Major;
        uint16_t Minor;
        uint16_t Build;
        uint16_t Revision;
    };
    inline bool operator==(GameControllerVersionInfo const& left, GameControllerVersionInfo const& right) noexcept
    {
        return left.Major == right.Major && left.Minor == right.Minor && left.Build == right.Build && left.Revision == right.Revision;
    }
    inline bool operator!=(GameControllerVersionInfo const& left, GameControllerVersionInfo const& right) noexcept
    {
        return !(left == right);
    }
    struct GipFirmwareUpdateProgress
    {
        double PercentCompleted;
        uint32_t CurrentComponentId;
    };
    inline bool operator==(GipFirmwareUpdateProgress const& left, GipFirmwareUpdateProgress const& right) noexcept
    {
        return left.PercentCompleted == right.PercentCompleted && left.CurrentComponentId == right.CurrentComponentId;
    }
    inline bool operator!=(GipFirmwareUpdateProgress const& left, GipFirmwareUpdateProgress const& right) noexcept
    {
        return !(left == right);
    }
    struct GameControllerFactoryManager
    {
        GameControllerFactoryManager() = delete;
        static auto RegisterCustomFactoryForGipInterface(winrt::Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, winrt::guid const& interfaceId);
        static auto RegisterCustomFactoryForHardwareId(winrt::Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, uint16_t hardwareVendorId, uint16_t hardwareProductId);
        static auto RegisterCustomFactoryForXusbType(winrt::Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, winrt::Windows::Gaming::Input::Custom::XusbDeviceType const& xusbType, winrt::Windows::Gaming::Input::Custom::XusbDeviceSubtype const& xusbSubtype);
        static auto TryGetFactoryControllerFromGameController(winrt::Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, winrt::Windows::Gaming::Input::IGameController const& gameController);
    };
    struct __declspec(empty_bases) GipFirmwareUpdateResult : winrt::Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult
    {
        GipFirmwareUpdateResult(std::nullptr_t) noexcept {}
        GipFirmwareUpdateResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) GipGameControllerProvider : winrt::Windows::Gaming::Input::Custom::IGipGameControllerProvider
    {
        GipGameControllerProvider(std::nullptr_t) noexcept {}
        GipGameControllerProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::Custom::IGipGameControllerProvider(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) HidGameControllerProvider : winrt::Windows::Gaming::Input::Custom::IHidGameControllerProvider
    {
        HidGameControllerProvider(std::nullptr_t) noexcept {}
        HidGameControllerProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::Custom::IHidGameControllerProvider(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XusbGameControllerProvider : winrt::Windows::Gaming::Input::Custom::IXusbGameControllerProvider
    {
        XusbGameControllerProvider(std::nullptr_t) noexcept {}
        XusbGameControllerProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::Custom::IXusbGameControllerProvider(ptr, take_ownership_from_abi) {}
    };
}
#endif
