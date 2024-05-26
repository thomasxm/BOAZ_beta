// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Core_0_H
#define WINRT_Windows_UI_Input_Core_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core
{
    struct CoreApplicationView;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct DispatcherQueue;
}
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    struct CoreDispatcher;
}
WINRT_EXPORT namespace winrt::Windows::UI::Input
{
    struct RadialController;
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Core
{
    struct IRadialControllerIndependentInputSource;
    struct IRadialControllerIndependentInputSource2;
    struct IRadialControllerIndependentInputSourceStatics;
    struct RadialControllerIndependentInputSource;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource> = L"Windows.UI.Input.Core.RadialControllerIndependentInputSource";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource> = L"Windows.UI.Input.Core.IRadialControllerIndependentInputSource";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2> = L"Windows.UI.Input.Core.IRadialControllerIndependentInputSource2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics> = L"Windows.UI.Input.Core.IRadialControllerIndependentInputSourceStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource>{ 0x3D577EF6,0x4CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF6-4CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>{ 0x7073AAD8,0x35F3,0x4EEB,{ 0x87,0x51,0xBE,0x4D,0x0A,0x66,0xFA,0xF4 } }; // 7073AAD8-35F3-4EEB-8751-BE4D0A66FAF4
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>{ 0x3D577EF5,0x4CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF5-4CEE-11E6-B535-001BDC06AB3B
    template <> struct default_interface<winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource>{ using type = winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource; };
    template <> struct abi<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Controller(void**) noexcept = 0;
            virtual int32_t __stdcall get_Dispatcher(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DispatcherQueue(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateForView(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) Controller() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreDispatcher) Dispatcher() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource>
    {
        template <typename D> using type = consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) DispatcherQueue() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>
    {
        template <typename D> using type = consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSourceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource) CreateForView(winrt::Windows::ApplicationModel::Core::CoreApplicationView const& view) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSourceStatics<D>;
    };
}
#endif
