// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Gaming_Input_1_H
#define WINRT_Windows_Gaming_Input_1_H
#include "winrt/impl/Windows.Gaming.Input.0.h"
WINRT_EXPORT namespace winrt::Windows::Gaming::Input
{
    struct __declspec(empty_bases) IArcadeStick :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IArcadeStick>,
        impl::require<winrt::Windows::Gaming::Input::IArcadeStick, winrt::Windows::Gaming::Input::IGameController>
    {
        IArcadeStick(std::nullptr_t = nullptr) noexcept {}
        IArcadeStick(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IArcadeStickStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IArcadeStickStatics>
    {
        IArcadeStickStatics(std::nullptr_t = nullptr) noexcept {}
        IArcadeStickStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IArcadeStickStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IArcadeStickStatics2>,
        impl::require<winrt::Windows::Gaming::Input::IArcadeStickStatics2, winrt::Windows::Gaming::Input::IArcadeStickStatics>
    {
        IArcadeStickStatics2(std::nullptr_t = nullptr) noexcept {}
        IArcadeStickStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFlightStick :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFlightStick>,
        impl::require<winrt::Windows::Gaming::Input::IFlightStick, winrt::Windows::Gaming::Input::IGameController>
    {
        IFlightStick(std::nullptr_t = nullptr) noexcept {}
        IFlightStick(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFlightStickStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFlightStickStatics>
    {
        IFlightStickStatics(std::nullptr_t = nullptr) noexcept {}
        IFlightStickStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameController>
    {
        IGameController(std::nullptr_t = nullptr) noexcept {}
        IGameController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGameControllerBatteryInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGameControllerBatteryInfo>
    {
        IGameControllerBatteryInfo(std::nullptr_t = nullptr) noexcept {}
        IGameControllerBatteryInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGamepad :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGamepad>,
        impl::require<winrt::Windows::Gaming::Input::IGamepad, winrt::Windows::Gaming::Input::IGameController>
    {
        IGamepad(std::nullptr_t = nullptr) noexcept {}
        IGamepad(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGamepad2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGamepad2>,
        impl::require<winrt::Windows::Gaming::Input::IGamepad2, winrt::Windows::Gaming::Input::IGameController, winrt::Windows::Gaming::Input::IGamepad>
    {
        IGamepad2(std::nullptr_t = nullptr) noexcept {}
        IGamepad2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGamepadStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGamepadStatics>
    {
        IGamepadStatics(std::nullptr_t = nullptr) noexcept {}
        IGamepadStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGamepadStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGamepadStatics2>,
        impl::require<winrt::Windows::Gaming::Input::IGamepadStatics2, winrt::Windows::Gaming::Input::IGamepadStatics>
    {
        IGamepadStatics2(std::nullptr_t = nullptr) noexcept {}
        IGamepadStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHeadset :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHeadset>
    {
        IHeadset(std::nullptr_t = nullptr) noexcept {}
        IHeadset(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRacingWheel :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRacingWheel>,
        impl::require<winrt::Windows::Gaming::Input::IRacingWheel, winrt::Windows::Gaming::Input::IGameController>
    {
        IRacingWheel(std::nullptr_t = nullptr) noexcept {}
        IRacingWheel(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRacingWheelStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRacingWheelStatics>
    {
        IRacingWheelStatics(std::nullptr_t = nullptr) noexcept {}
        IRacingWheelStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRacingWheelStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRacingWheelStatics2>,
        impl::require<winrt::Windows::Gaming::Input::IRacingWheelStatics2, winrt::Windows::Gaming::Input::IRacingWheelStatics>
    {
        IRacingWheelStatics2(std::nullptr_t = nullptr) noexcept {}
        IRacingWheelStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRawGameController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRawGameController>,
        impl::require<winrt::Windows::Gaming::Input::IRawGameController, winrt::Windows::Gaming::Input::IGameController>
    {
        IRawGameController(std::nullptr_t = nullptr) noexcept {}
        IRawGameController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRawGameController2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRawGameController2>,
        impl::require<winrt::Windows::Gaming::Input::IRawGameController2, winrt::Windows::Gaming::Input::IGameController, winrt::Windows::Gaming::Input::IRawGameController>
    {
        IRawGameController2(std::nullptr_t = nullptr) noexcept {}
        IRawGameController2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRawGameControllerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRawGameControllerStatics>
    {
        IRawGameControllerStatics(std::nullptr_t = nullptr) noexcept {}
        IRawGameControllerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUINavigationController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUINavigationController>,
        impl::require<winrt::Windows::Gaming::Input::IUINavigationController, winrt::Windows::Gaming::Input::IGameController>
    {
        IUINavigationController(std::nullptr_t = nullptr) noexcept {}
        IUINavigationController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUINavigationControllerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUINavigationControllerStatics>
    {
        IUINavigationControllerStatics(std::nullptr_t = nullptr) noexcept {}
        IUINavigationControllerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUINavigationControllerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUINavigationControllerStatics2>,
        impl::require<winrt::Windows::Gaming::Input::IUINavigationControllerStatics2, winrt::Windows::Gaming::Input::IUINavigationControllerStatics>
    {
        IUINavigationControllerStatics2(std::nullptr_t = nullptr) noexcept {}
        IUINavigationControllerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
