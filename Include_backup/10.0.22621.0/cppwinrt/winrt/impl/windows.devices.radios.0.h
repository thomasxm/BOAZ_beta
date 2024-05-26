// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Radios_0_H
#define WINRT_Windows_Devices_Radios_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Radios
{
    enum class RadioAccessStatus : int32_t
    {
        Unspecified = 0,
        Allowed = 1,
        DeniedByUser = 2,
        DeniedBySystem = 3,
    };
    enum class RadioKind : int32_t
    {
        Other = 0,
        WiFi = 1,
        MobileBroadband = 2,
        Bluetooth = 3,
        FM = 4,
    };
    enum class RadioState : int32_t
    {
        Unknown = 0,
        On = 1,
        Off = 2,
        Disabled = 3,
    };
    struct IRadio;
    struct IRadioStatics;
    struct Radio;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Radios::IRadio>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Radios::IRadioStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Radios::Radio>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Radios::RadioAccessStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Radios::RadioKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Radios::RadioState>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Radios::Radio> = L"Windows.Devices.Radios.Radio";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Radios::RadioAccessStatus> = L"Windows.Devices.Radios.RadioAccessStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Radios::RadioKind> = L"Windows.Devices.Radios.RadioKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Radios::RadioState> = L"Windows.Devices.Radios.RadioState";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Radios::IRadio> = L"Windows.Devices.Radios.IRadio";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Radios::IRadioStatics> = L"Windows.Devices.Radios.IRadioStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Radios::IRadio>{ 0x252118DF,0xB33E,0x416A,{ 0x87,0x5F,0x1C,0xF3,0x8A,0xE2,0xD8,0x3E } }; // 252118DF-B33E-416A-875F-1CF38AE2D83E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Radios::IRadioStatics>{ 0x5FB6A12E,0x67CB,0x46AE,{ 0xAA,0xE9,0x65,0x91,0x9F,0x86,0xEF,0xF4 } }; // 5FB6A12E-67CB-46AE-AAE9-65919F86EFF4
    template <> struct default_interface<winrt::Windows::Devices::Radios::Radio>{ using type = winrt::Windows::Devices::Radios::IRadio; };
    template <> struct abi<winrt::Windows::Devices::Radios::IRadio>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetStateAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall add_StateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StateChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Kind(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Radios::IRadioStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetRadiosAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessAsync(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Radios_IRadio
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>) SetStateAsync(winrt::Windows::Devices::Radios::RadioState const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Radios::Radio, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using StateChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Radios::IRadio, &impl::abi_t<winrt::Windows::Devices::Radios::IRadio>::remove_StateChanged>;
        [[nodiscard]] StateChanged_revoker StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Radios::Radio, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) StateChanged(winrt::event_token const& eventCookie) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Radios::RadioState) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Radios::RadioKind) Kind() const;
    };
    template <> struct consume<winrt::Windows::Devices::Radios::IRadio>
    {
        template <typename D> using type = consume_Windows_Devices_Radios_IRadio<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Radios_IRadioStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Radios::Radio>>) GetRadiosAsync() const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::RadioAccessStatus>) RequestAccessAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::Radios::IRadioStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Radios_IRadioStatics<D>;
    };
}
#endif
