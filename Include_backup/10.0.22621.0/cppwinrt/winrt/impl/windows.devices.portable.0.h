// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Portable_0_H
#define WINRT_Windows_Devices_Portable_0_H
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct StorageFolder;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Portable
{
    enum class ServiceDeviceType : int32_t
    {
        CalendarService = 0,
        ContactsService = 1,
        DeviceStatusService = 2,
        NotesService = 3,
        RingtonesService = 4,
        SmsService = 5,
        TasksService = 6,
    };
    struct IServiceDeviceStatics;
    struct IStorageDeviceStatics;
    struct ServiceDevice;
    struct StorageDevice;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Portable::IServiceDeviceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Portable::IStorageDeviceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Portable::ServiceDevice>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Portable::StorageDevice>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Portable::ServiceDeviceType>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Portable::ServiceDevice> = L"Windows.Devices.Portable.ServiceDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Portable::StorageDevice> = L"Windows.Devices.Portable.StorageDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Portable::ServiceDeviceType> = L"Windows.Devices.Portable.ServiceDeviceType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Portable::IServiceDeviceStatics> = L"Windows.Devices.Portable.IServiceDeviceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Portable::IStorageDeviceStatics> = L"Windows.Devices.Portable.IStorageDeviceStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Portable::IServiceDeviceStatics>{ 0xA88214E1,0x59C7,0x4A20,{ 0xAB,0xA6,0x9F,0x67,0x07,0x93,0x72,0x30 } }; // A88214E1-59C7-4A20-ABA6-9F6707937230
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Portable::IStorageDeviceStatics>{ 0x5ECE44EE,0x1B23,0x4DD2,{ 0x86,0x52,0xBC,0x16,0x4F,0x00,0x31,0x28 } }; // 5ECE44EE-1B23-4DD2-8652-BC164F003128
    template <> struct abi<winrt::Windows::Devices::Portable::IServiceDeviceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromServiceId(winrt::guid, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Portable::IStorageDeviceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromId(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Portable_IServiceDeviceStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::Portable::ServiceDeviceType const& serviceType) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromServiceId(winrt::guid const& serviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Portable::IServiceDeviceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Portable_IServiceDeviceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Portable_IStorageDeviceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFolder) FromId(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::Portable::IStorageDeviceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Portable_IStorageDeviceStatics<D>;
    };
}
#endif
