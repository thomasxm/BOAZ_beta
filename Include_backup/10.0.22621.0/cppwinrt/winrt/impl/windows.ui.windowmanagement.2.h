// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_WindowManagement_2_H
#define WINRT_Windows_UI_WindowManagement_2_H
#include "winrt/impl/Windows.UI.WindowManagement.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement
{
    struct __declspec(empty_bases) AppWindow : winrt::Windows::UI::WindowManagement::IAppWindow
    {
        AppWindow(std::nullptr_t) noexcept {}
        AppWindow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindow(ptr, take_ownership_from_abi) {}
        static auto TryCreateAsync();
        static auto ClearAllPersistedState();
        static auto ClearPersistedState(param::hstring const& key);
    };
    struct __declspec(empty_bases) AppWindowChangedEventArgs : winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs
    {
        AppWindowChangedEventArgs(std::nullptr_t) noexcept {}
        AppWindowChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowCloseRequestedEventArgs : winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs
    {
        AppWindowCloseRequestedEventArgs(std::nullptr_t) noexcept {}
        AppWindowCloseRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowClosedEventArgs : winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs
    {
        AppWindowClosedEventArgs(std::nullptr_t) noexcept {}
        AppWindowClosedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowFrame : winrt::Windows::UI::WindowManagement::IAppWindowFrame,
        impl::require<AppWindowFrame, winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle>
    {
        AppWindowFrame(std::nullptr_t) noexcept {}
        AppWindowFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowPlacement : winrt::Windows::UI::WindowManagement::IAppWindowPlacement
    {
        AppWindowPlacement(std::nullptr_t) noexcept {}
        AppWindowPlacement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowPlacement(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowPresentationConfiguration : winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration
    {
        AppWindowPresentationConfiguration(std::nullptr_t) noexcept {}
        AppWindowPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowPresenter : winrt::Windows::UI::WindowManagement::IAppWindowPresenter
    {
        AppWindowPresenter(std::nullptr_t) noexcept {}
        AppWindowPresenter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowPresenter(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowTitleBar : winrt::Windows::UI::WindowManagement::IAppWindowTitleBar,
        impl::require<AppWindowTitleBar, winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility>
    {
        AppWindowTitleBar(std::nullptr_t) noexcept {}
        AppWindowTitleBar(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowTitleBar(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) AppWindowTitleBarOcclusion : winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion
    {
        AppWindowTitleBarOcclusion(std::nullptr_t) noexcept {}
        AppWindowTitleBarOcclusion(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CompactOverlayPresentationConfiguration : winrt::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration,
        impl::base<CompactOverlayPresentationConfiguration, winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration>,
        impl::require<CompactOverlayPresentationConfiguration, winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
    {
        CompactOverlayPresentationConfiguration(std::nullptr_t) noexcept {}
        CompactOverlayPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration(ptr, take_ownership_from_abi) {}
        CompactOverlayPresentationConfiguration();
    };
    struct __declspec(empty_bases) DefaultPresentationConfiguration : winrt::Windows::UI::WindowManagement::IDefaultPresentationConfiguration,
        impl::base<DefaultPresentationConfiguration, winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration>,
        impl::require<DefaultPresentationConfiguration, winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
    {
        DefaultPresentationConfiguration(std::nullptr_t) noexcept {}
        DefaultPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IDefaultPresentationConfiguration(ptr, take_ownership_from_abi) {}
        DefaultPresentationConfiguration();
    };
    struct __declspec(empty_bases) DisplayRegion : winrt::Windows::UI::WindowManagement::IDisplayRegion
    {
        DisplayRegion(std::nullptr_t) noexcept {}
        DisplayRegion(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IDisplayRegion(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FullScreenPresentationConfiguration : winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration,
        impl::base<FullScreenPresentationConfiguration, winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration>,
        impl::require<FullScreenPresentationConfiguration, winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
    {
        FullScreenPresentationConfiguration(std::nullptr_t) noexcept {}
        FullScreenPresentationConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration(ptr, take_ownership_from_abi) {}
        FullScreenPresentationConfiguration();
    };
    struct WindowServices
    {
        WindowServices() = delete;
        static auto FindAllTopLevelWindowIds();
    };
    struct __declspec(empty_bases) WindowingEnvironment : winrt::Windows::UI::WindowManagement::IWindowingEnvironment
    {
        WindowingEnvironment(std::nullptr_t) noexcept {}
        WindowingEnvironment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IWindowingEnvironment(ptr, take_ownership_from_abi) {}
        static auto FindAll();
        static auto FindAll(winrt::Windows::UI::WindowManagement::WindowingEnvironmentKind const& kind);
    };
    struct __declspec(empty_bases) WindowingEnvironmentAddedEventArgs : winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs
    {
        WindowingEnvironmentAddedEventArgs(std::nullptr_t) noexcept {}
        WindowingEnvironmentAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WindowingEnvironmentChangedEventArgs : winrt::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs
    {
        WindowingEnvironmentChangedEventArgs(std::nullptr_t) noexcept {}
        WindowingEnvironmentChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) WindowingEnvironmentRemovedEventArgs : winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs
    {
        WindowingEnvironmentRemovedEventArgs(std::nullptr_t) noexcept {}
        WindowingEnvironmentRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
