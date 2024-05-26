// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Power_Diagnostics_0_H
#define WINRT_Windows_System_Power_Diagnostics_0_H
WINRT_EXPORT namespace winrt::Windows::System::Power::Diagnostics
{
    struct IBackgroundEnergyDiagnosticsStatics;
    struct IForegroundEnergyDiagnosticsStatics;
    struct BackgroundEnergyDiagnostics;
    struct ForegroundEnergyDiagnostics;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::Power::Diagnostics::BackgroundEnergyDiagnostics>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::Power::Diagnostics::ForegroundEnergyDiagnostics>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::System::Power::Diagnostics::BackgroundEnergyDiagnostics> = L"Windows.System.Power.Diagnostics.BackgroundEnergyDiagnostics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Power::Diagnostics::ForegroundEnergyDiagnostics> = L"Windows.System.Power.Diagnostics.ForegroundEnergyDiagnostics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics> = L"Windows.System.Power.Diagnostics.IBackgroundEnergyDiagnosticsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics> = L"Windows.System.Power.Diagnostics.IForegroundEnergyDiagnosticsStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>{ 0xD7663702,0xD3A6,0x46E0,{ 0x8F,0x9B,0x50,0xB9,0x5B,0xB4,0xF9,0xC5 } }; // D7663702-D3A6-46E0-8F9B-50B95BB4F9C5
    template <> inline constexpr guid guid_v<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>{ 0x23CA0917,0xCD07,0x4609,{ 0xBE,0x15,0x8F,0xE8,0x94,0xC5,0xE4,0x1E } }; // 23CA0917-CD07-4609-BE15-8FE894C5E41E
    template <> struct abi<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceSpecificConversionFactor(double*) noexcept = 0;
            virtual int32_t __stdcall ComputeTotalEnergyUsage(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall ResetTotalEnergyUsage() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceSpecificConversionFactor(double*) noexcept = 0;
            virtual int32_t __stdcall ComputeTotalEnergyUsage(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall ResetTotalEnergyUsage() noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) DeviceSpecificConversionFactor() const;
        WINRT_IMPL_AUTO(uint64_t) ComputeTotalEnergyUsage() const;
        WINRT_IMPL_AUTO(void) ResetTotalEnergyUsage() const;
    };
    template <> struct consume<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>
    {
        template <typename D> using type = consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) DeviceSpecificConversionFactor() const;
        WINRT_IMPL_AUTO(uint64_t) ComputeTotalEnergyUsage() const;
        WINRT_IMPL_AUTO(void) ResetTotalEnergyUsage() const;
    };
    template <> struct consume<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>
    {
        template <typename D> using type = consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics<D>;
    };
}
#endif
