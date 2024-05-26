// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Power_Diagnostics_H
#define WINRT_Windows_System_Power_Diagnostics_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.Power.h"
#include "winrt/impl/Windows.System.Power.Diagnostics.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics<D>::DeviceSpecificConversionFactor() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics)->get_DeviceSpecificConversionFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics<D>::ComputeTotalEnergyUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics)->ComputeTotalEnergyUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics<D>::ResetTotalEnergyUsage() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics)->ResetTotalEnergyUsage());
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics<D>::DeviceSpecificConversionFactor() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics)->get_DeviceSpecificConversionFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics<D>::ComputeTotalEnergyUsage() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics)->ComputeTotalEnergyUsage(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics<D>::ResetTotalEnergyUsage() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics)->ResetTotalEnergyUsage());
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics> : produce_base<D, winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>
    {
        int32_t __stdcall get_DeviceSpecificConversionFactor(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DeviceSpecificConversionFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ComputeTotalEnergyUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ComputeTotalEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetTotalEnergyUsage() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetTotalEnergyUsage();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics> : produce_base<D, winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>
    {
        int32_t __stdcall get_DeviceSpecificConversionFactor(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DeviceSpecificConversionFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ComputeTotalEnergyUsage(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ComputeTotalEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResetTotalEnergyUsage() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetTotalEnergyUsage();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Power::Diagnostics
{
    inline auto BackgroundEnergyDiagnostics::DeviceSpecificConversionFactor()
    {
        return impl::call_factory_cast<double(*)(IBackgroundEnergyDiagnosticsStatics const&), BackgroundEnergyDiagnostics, IBackgroundEnergyDiagnosticsStatics>([](IBackgroundEnergyDiagnosticsStatics const& f) { return f.DeviceSpecificConversionFactor(); });
    }
    inline auto BackgroundEnergyDiagnostics::ComputeTotalEnergyUsage()
    {
        return impl::call_factory_cast<uint64_t(*)(IBackgroundEnergyDiagnosticsStatics const&), BackgroundEnergyDiagnostics, IBackgroundEnergyDiagnosticsStatics>([](IBackgroundEnergyDiagnosticsStatics const& f) { return f.ComputeTotalEnergyUsage(); });
    }
    inline auto BackgroundEnergyDiagnostics::ResetTotalEnergyUsage()
    {
        impl::call_factory_cast<void(*)(IBackgroundEnergyDiagnosticsStatics const&), BackgroundEnergyDiagnostics, IBackgroundEnergyDiagnosticsStatics>([](IBackgroundEnergyDiagnosticsStatics const& f) { return f.ResetTotalEnergyUsage(); });
    }
    inline auto ForegroundEnergyDiagnostics::DeviceSpecificConversionFactor()
    {
        return impl::call_factory_cast<double(*)(IForegroundEnergyDiagnosticsStatics const&), ForegroundEnergyDiagnostics, IForegroundEnergyDiagnosticsStatics>([](IForegroundEnergyDiagnosticsStatics const& f) { return f.DeviceSpecificConversionFactor(); });
    }
    inline auto ForegroundEnergyDiagnostics::ComputeTotalEnergyUsage()
    {
        return impl::call_factory_cast<uint64_t(*)(IForegroundEnergyDiagnosticsStatics const&), ForegroundEnergyDiagnostics, IForegroundEnergyDiagnosticsStatics>([](IForegroundEnergyDiagnosticsStatics const& f) { return f.ComputeTotalEnergyUsage(); });
    }
    inline auto ForegroundEnergyDiagnostics::ResetTotalEnergyUsage()
    {
        impl::call_factory_cast<void(*)(IForegroundEnergyDiagnosticsStatics const&), ForegroundEnergyDiagnostics, IForegroundEnergyDiagnosticsStatics>([](IForegroundEnergyDiagnosticsStatics const& f) { return f.ResetTotalEnergyUsage(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::Diagnostics::BackgroundEnergyDiagnostics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Power::Diagnostics::ForegroundEnergyDiagnostics> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
