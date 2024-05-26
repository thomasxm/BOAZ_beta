// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Gaming_Input_Preview_0_H
#define WINRT_Windows_Gaming_Input_Preview_0_H
WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Custom
{
    struct IGameControllerProvider;
}
WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Preview
{
    struct IGameControllerProviderInfoStatics;
    struct GameControllerProviderInfo;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Gaming::Input::Preview::GameControllerProviderInfo>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::Input::Preview::GameControllerProviderInfo> = L"Windows.Gaming.Input.Preview.GameControllerProviderInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics> = L"Windows.Gaming.Input.Preview.IGameControllerProviderInfoStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics>{ 0x0BE1E6C5,0xD9BD,0x44EE,{ 0x83,0x62,0x48,0x8B,0x2E,0x46,0x4B,0xFB } }; // 0BE1E6C5-D9BD-44EE-8362-488B2E464BFB
    template <> struct abi<winrt::Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetParentProviderId(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetProviderId(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Gaming_Input_Preview_IGameControllerProviderInfoStatics
    {
        WINRT_IMPL_AUTO(hstring) GetParentProviderId(winrt::Windows::Gaming::Input::Custom::IGameControllerProvider const& provider) const;
        WINRT_IMPL_AUTO(hstring) GetProviderId(winrt::Windows::Gaming::Input::Custom::IGameControllerProvider const& provider) const;
    };
    template <> struct consume<winrt::Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics>
    {
        template <typename D> using type = consume_Windows_Gaming_Input_Preview_IGameControllerProviderInfoStatics<D>;
    };
}
#endif
