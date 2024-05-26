// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Geolocation_Provider_0_H
#define WINRT_Windows_Devices_Geolocation_Provider_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation
{
    struct BasicGeoposition;
    enum class PositionSource : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation::Provider
{
    enum class LocationOverrideStatus : int32_t
    {
        Success = 0,
        AccessDenied = 1,
        AlreadyStarted = 2,
        Other = 3,
    };
    struct IGeolocationProvider;
    struct GeolocationProvider;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Geolocation::Provider::GeolocationProvider>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Geolocation::Provider::LocationOverrideStatus>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Geolocation::Provider::GeolocationProvider> = L"Windows.Devices.Geolocation.Provider.GeolocationProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Geolocation::Provider::LocationOverrideStatus> = L"Windows.Devices.Geolocation.Provider.LocationOverrideStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider> = L"Windows.Devices.Geolocation.Provider.IGeolocationProvider";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider>{ 0xE4CF071D,0x3F64,0x509F,{ 0x8D,0xC2,0x0B,0x74,0xA0,0x59,0x82,0x9D } }; // E4CF071D-3F64-509F-8DC2-0B74A059829D
    template <> struct default_interface<winrt::Windows::Devices::Geolocation::Provider::GeolocationProvider>{ using type = winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider; };
    template <> struct abi<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsOverridden(bool*) noexcept = 0;
            virtual int32_t __stdcall SetOverridePosition(struct struct_Windows_Devices_Geolocation_BasicGeoposition, int32_t, double, int32_t*) noexcept = 0;
            virtual int32_t __stdcall ClearOverridePosition() noexcept = 0;
            virtual int32_t __stdcall add_IsOverriddenChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_IsOverriddenChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOverridden() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::Provider::LocationOverrideStatus) SetOverridePosition(winrt::Windows::Devices::Geolocation::BasicGeoposition const& newPosition, winrt::Windows::Devices::Geolocation::PositionSource const& positionSource, double accuracyInMeters) const;
        WINRT_IMPL_AUTO(void) ClearOverridePosition() const;
        WINRT_IMPL_AUTO(winrt::event_token) IsOverriddenChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        using IsOverriddenChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider, &impl::abi_t<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider>::remove_IsOverriddenChanged>;
        [[nodiscard]] IsOverriddenChanged_revoker IsOverriddenChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) IsOverriddenChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Geolocation::Provider::IGeolocationProvider>
    {
        template <typename D> using type = consume_Windows_Devices_Geolocation_Provider_IGeolocationProvider<D>;
    };
}
#endif
