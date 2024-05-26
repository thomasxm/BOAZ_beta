// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Sensors_Custom_0_H
#define WINRT_Windows_Devices_Sensors_Custom_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Sensors::Custom
{
    struct ICustomSensor;
    struct ICustomSensor2;
    struct ICustomSensorReading;
    struct ICustomSensorReading2;
    struct ICustomSensorReadingChangedEventArgs;
    struct ICustomSensorStatics;
    struct CustomSensor;
    struct CustomSensorReading;
    struct CustomSensorReadingChangedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::ICustomSensor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::CustomSensor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::CustomSensor> = L"Windows.Devices.Sensors.Custom.CustomSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading> = L"Windows.Devices.Sensors.Custom.CustomSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.Custom.CustomSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensor> = L"Windows.Devices.Sensors.Custom.ICustomSensor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2> = L"Windows.Devices.Sensors.Custom.ICustomSensor2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading> = L"Windows.Devices.Sensors.Custom.ICustomSensorReading";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2> = L"Windows.Devices.Sensors.Custom.ICustomSensorReading2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs> = L"Windows.Devices.Sensors.Custom.ICustomSensorReadingChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics> = L"Windows.Devices.Sensors.Custom.ICustomSensorStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensor>{ 0xA136F9AD,0x4034,0x4B4D,{ 0x99,0xDD,0x53,0x1A,0xAC,0x64,0x9C,0x09 } }; // A136F9AD-4034-4B4D-99DD-531AAC649C09
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2>{ 0x20DB3111,0xEC58,0x4D9F,{ 0xBF,0xBD,0xE7,0x78,0x25,0x08,0x85,0x10 } }; // 20DB3111-EC58-4D9F-BFBD-E77825088510
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading>{ 0x64004F4D,0x446A,0x4366,{ 0xA8,0x7A,0x5F,0x96,0x32,0x68,0xEC,0x53 } }; // 64004F4D-446A-4366-A87A-5F963268EC53
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2>{ 0x223C98EA,0xBF73,0x4992,{ 0x9A,0x48,0xD3,0xC8,0x97,0x59,0x4C,0xCB } }; // 223C98EA-BF73-4992-9A48-D3C897594CCB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs>{ 0x6B202023,0xCFFD,0x4CC1,{ 0x8F,0xF0,0xE2,0x18,0x23,0xD7,0x6F,0xCC } }; // 6B202023-CFFD-4CC1-8FF0-E21823D76FCC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics>{ 0x992052CF,0xF422,0x4C7D,{ 0x83,0x6B,0xE7,0xDC,0x74,0xA7,0x12,0x4B } }; // 992052CF-F422-4C7D-836B-E7DC74A7124B
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Custom::CustomSensor>{ using type = winrt::Windows::Devices::Sensors::Custom::ICustomSensor; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading>{ using type = winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading; };
    template <> struct default_interface<winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs>{ using type = winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs; };
    template <> struct abi<winrt::Windows::Devices::Sensors::Custom::ICustomSensor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentReading(void**) noexcept = 0;
            virtual int32_t __stdcall get_MinimumReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReportInterval(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportInterval(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall add_ReadingChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReadingChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ReportLatency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ReportLatency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxBatchSize(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PerformanceCount(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Reading(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(winrt::guid, void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_Custom_ICustomSensor
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Custom::CustomSensorReading) GetCurrentReading() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MinimumReportInterval() const;
        WINRT_IMPL_AUTO(void) ReportInterval(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportInterval() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReadingChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Custom::CustomSensor, winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const& handler) const;
        using ReadingChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Sensors::Custom::ICustomSensor, &impl::abi_t<winrt::Windows::Devices::Sensors::Custom::ICustomSensor>::remove_ReadingChanged>;
        [[nodiscard]] ReadingChanged_revoker ReadingChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Sensors::Custom::CustomSensor, winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReadingChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::Custom::ICustomSensor>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_Custom_ICustomSensor2
    {
        WINRT_IMPL_AUTO(void) ReportLatency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ReportLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxBatchSize() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_Custom_ICustomSensor2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_Custom_ICustomSensorReading
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::IInspectable>) Properties() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_Custom_ICustomSensorReading<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_Custom_ICustomSensorReading2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) PerformanceCount() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_Custom_ICustomSensorReading2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_Custom_ICustomSensorReadingChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Sensors::Custom::CustomSensorReading) Reading() const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_Custom_ICustomSensorReadingChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Sensors_Custom_ICustomSensorStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::guid const& interfaceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Sensors::Custom::CustomSensor>) FromIdAsync(param::hstring const& sensorId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Sensors_Custom_ICustomSensorStatics<D>;
    };
}
#endif
