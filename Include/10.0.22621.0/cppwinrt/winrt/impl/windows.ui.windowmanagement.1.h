// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WindowManagement_1_H
#define WINRT_Windows_UI_WindowManagement_1_H
#include "winrt/impl/Windows.UI.WindowManagement.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement
{
    struct __declspec(empty_bases) IAppWindow :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindow>
    {
        IAppWindow(std::nullptr_t = nullptr) noexcept {}
        IAppWindow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowChangedEventArgs>
    {
        IAppWindowChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppWindowChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowCloseRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowCloseRequestedEventArgs>
    {
        IAppWindowCloseRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppWindowCloseRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowClosedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowClosedEventArgs>
    {
        IAppWindowClosedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAppWindowClosedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowFrame :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowFrame>
    {
        IAppWindowFrame(std::nullptr_t = nullptr) noexcept {}
        IAppWindowFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowFrameStyle :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowFrameStyle>
    {
        IAppWindowFrameStyle(std::nullptr_t = nullptr) noexcept {}
        IAppWindowFrameStyle(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowPlacement :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowPlacement>
    {
        IAppWindowPlacement(std::nullptr_t = nullptr) noexcept {}
        IAppWindowPlacement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowPresentationConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowPresentationConfiguration>
    {
        IAppWindowPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
        IAppWindowPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowPresentationConfigurationFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowPresentationConfigurationFactory>
    {
        IAppWindowPresentationConfigurationFactory(std::nullptr_t = nullptr) noexcept {}
        IAppWindowPresentationConfigurationFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowPresenter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowPresenter>
    {
        IAppWindowPresenter(std::nullptr_t = nullptr) noexcept {}
        IAppWindowPresenter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowStatics>
    {
        IAppWindowStatics(std::nullptr_t = nullptr) noexcept {}
        IAppWindowStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowTitleBar :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowTitleBar>
    {
        IAppWindowTitleBar(std::nullptr_t = nullptr) noexcept {}
        IAppWindowTitleBar(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowTitleBarOcclusion :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowTitleBarOcclusion>
    {
        IAppWindowTitleBarOcclusion(std::nullptr_t = nullptr) noexcept {}
        IAppWindowTitleBarOcclusion(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAppWindowTitleBarVisibility :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAppWindowTitleBarVisibility>
    {
        IAppWindowTitleBarVisibility(std::nullptr_t = nullptr) noexcept {}
        IAppWindowTitleBarVisibility(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICompactOverlayPresentationConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICompactOverlayPresentationConfiguration>
    {
        ICompactOverlayPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
        ICompactOverlayPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDefaultPresentationConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDefaultPresentationConfiguration>
    {
        IDefaultPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
        IDefaultPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDisplayRegion :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDisplayRegion>
    {
        IDisplayRegion(std::nullptr_t = nullptr) noexcept {}
        IDisplayRegion(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFullScreenPresentationConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFullScreenPresentationConfiguration>
    {
        IFullScreenPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
        IFullScreenPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowServicesStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowServicesStatics>
    {
        IWindowServicesStatics(std::nullptr_t = nullptr) noexcept {}
        IWindowServicesStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowingEnvironment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowingEnvironment>
    {
        IWindowingEnvironment(std::nullptr_t = nullptr) noexcept {}
        IWindowingEnvironment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowingEnvironmentAddedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowingEnvironmentAddedEventArgs>
    {
        IWindowingEnvironmentAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowingEnvironmentAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowingEnvironmentChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowingEnvironmentChangedEventArgs>
    {
        IWindowingEnvironmentChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowingEnvironmentChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowingEnvironmentRemovedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowingEnvironmentRemovedEventArgs>
    {
        IWindowingEnvironmentRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowingEnvironmentRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowingEnvironmentStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowingEnvironmentStatics>
    {
        IWindowingEnvironmentStatics(std::nullptr_t = nullptr) noexcept {}
        IWindowingEnvironmentStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
