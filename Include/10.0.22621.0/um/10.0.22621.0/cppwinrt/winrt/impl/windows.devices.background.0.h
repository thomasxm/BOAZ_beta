// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Background_0_H
#define WINRT_Windows_Devices_Background_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
}
WINRT_EXPORT namespace winrt::Windows::Devices::Background
{
    struct IDeviceServicingDetails;
    struct IDeviceUseDetails;
    struct DeviceServicingDetails;
    struct DeviceUseDetails;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Background::IDeviceServicingDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Background::IDeviceUseDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Background::DeviceServicingDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Background::DeviceUseDetails>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Background::DeviceServicingDetails> = L"Windows.Devices.Background.DeviceServicingDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Background::DeviceUseDetails> = L"Windows.Devices.Background.DeviceUseDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Background::IDeviceServicingDetails> = L"Windows.Devices.Background.IDeviceServicingDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Background::IDeviceUseDetails> = L"Windows.Devices.Background.IDeviceUseDetails";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Background::IDeviceServicingDetails>{ 0x4AABEE29,0x2344,0x4AC4,{ 0x85,0x27,0x4A,0x8E,0xF6,0x90,0x56,0x45 } }; // 4AABEE29-2344-4AC4-8527-4A8EF6905645
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Background::IDeviceUseDetails>{ 0x7D565141,0x557E,0x4154,{ 0xB9,0x94,0xE4,0xF7,0xA1,0x1F,0xB3,0x23 } }; // 7D565141-557E-4154-B994-E4F7A11FB323
    template <> struct default_interface<winrt::Windows::Devices::Background::DeviceServicingDetails>{ using type = winrt::Windows::Devices::Background::IDeviceServicingDetails; };
    template <> struct default_interface<winrt::Windows::Devices::Background::DeviceUseDetails>{ using type = winrt::Windows::Devices::Background::IDeviceUseDetails; };
    template <> struct abi<winrt::Windows::Devices::Background::IDeviceServicingDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Arguments(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExpectedDuration(int64_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Background::IDeviceUseDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Arguments(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Background_IDeviceServicingDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Arguments() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) ExpectedDuration() const;
    };
    template <> struct consume<winrt::Windows::Devices::Background::IDeviceServicingDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Background_IDeviceServicingDetails<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Background_IDeviceUseDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Arguments() const;
    };
    template <> struct consume<winrt::Windows::Devices::Background::IDeviceUseDetails>
    {
        template <typename D> using type = consume_Windows_Devices_Background_IDeviceUseDetails<D>;
    };
}
#endif
