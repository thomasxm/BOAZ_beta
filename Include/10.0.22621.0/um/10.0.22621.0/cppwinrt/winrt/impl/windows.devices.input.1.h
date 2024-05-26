// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Input_1_H
#define WINRT_Windows_Devices_Input_1_H
#include "winrt/impl/Windows.Devices.Input.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Input
{
    struct __declspec(empty_bases) IKeyboardCapabilities :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyboardCapabilities>
    {
        IKeyboardCapabilities(std::nullptr_t = nullptr) noexcept {}
        IKeyboardCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMouseCapabilities :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMouseCapabilities>
    {
        IMouseCapabilities(std::nullptr_t = nullptr) noexcept {}
        IMouseCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMouseDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMouseDevice>
    {
        IMouseDevice(std::nullptr_t = nullptr) noexcept {}
        IMouseDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMouseDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMouseDeviceStatics>
    {
        IMouseDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IMouseDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMouseEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMouseEventArgs>
    {
        IMouseEventArgs(std::nullptr_t = nullptr) noexcept {}
        IMouseEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenButtonListener :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenButtonListener>
    {
        IPenButtonListener(std::nullptr_t = nullptr) noexcept {}
        IPenButtonListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenButtonListenerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenButtonListenerStatics>
    {
        IPenButtonListenerStatics(std::nullptr_t = nullptr) noexcept {}
        IPenButtonListenerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenDevice>
    {
        IPenDevice(std::nullptr_t = nullptr) noexcept {}
        IPenDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenDevice2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenDevice2>
    {
        IPenDevice2(std::nullptr_t = nullptr) noexcept {}
        IPenDevice2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenDeviceStatics>
    {
        IPenDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IPenDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenDockListener :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenDockListener>
    {
        IPenDockListener(std::nullptr_t = nullptr) noexcept {}
        IPenDockListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenDockListenerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenDockListenerStatics>
    {
        IPenDockListenerStatics(std::nullptr_t = nullptr) noexcept {}
        IPenDockListenerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenDockedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenDockedEventArgs>
    {
        IPenDockedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPenDockedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenTailButtonClickedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenTailButtonClickedEventArgs>
    {
        IPenTailButtonClickedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPenTailButtonClickedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenTailButtonDoubleClickedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenTailButtonDoubleClickedEventArgs>
    {
        IPenTailButtonDoubleClickedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPenTailButtonDoubleClickedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenTailButtonLongPressedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenTailButtonLongPressedEventArgs>
    {
        IPenTailButtonLongPressedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPenTailButtonLongPressedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPenUndockedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPenUndockedEventArgs>
    {
        IPenUndockedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPenUndockedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPointerDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPointerDevice>
    {
        IPointerDevice(std::nullptr_t = nullptr) noexcept {}
        IPointerDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPointerDevice2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPointerDevice2>
    {
        IPointerDevice2(std::nullptr_t = nullptr) noexcept {}
        IPointerDevice2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPointerDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPointerDeviceStatics>
    {
        IPointerDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IPointerDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITouchCapabilities :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITouchCapabilities>
    {
        ITouchCapabilities(std::nullptr_t = nullptr) noexcept {}
        ITouchCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
