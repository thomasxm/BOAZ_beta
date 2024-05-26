// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Diagnostics_Telemetry_H
#define WINRT_Windows_System_Diagnostics_Telemetry_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.System.Diagnostics.h"
#include "winrt/impl/Windows.System.Diagnostics.Telemetry.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult) consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryClientStatics<D>::Register(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics)->Register(*(void**)(&id), &result));
        return winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult) consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryClientStatics<D>::Register(param::hstring const& id, winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const& settings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics)->RegisterWithSettings(*(void**)(&id), *(void**)(&settings), &result));
        return winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus) consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationResult<D>::Status() const
    {
        winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::StorageSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->get_StorageSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::StorageSize(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->put_StorageSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::UploadQuotaSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->get_UploadQuotaSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_System_Diagnostics_Telemetry_IPlatformTelemetryRegistrationSettings<D>::UploadQuotaSize(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings)->put_UploadQuotaSize(value));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics> : produce_base<D, winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics>
    {
        int32_t __stdcall Register(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult>(this->shim().Register(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RegisterWithSettings(void* id, void* settings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult>(this->shim().Register(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult> : produce_base<D, winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings> : produce_base<D, winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings>
    {
        int32_t __stdcall get_StorageSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().StorageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StorageSize(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StorageSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UploadQuotaSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UploadQuotaSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UploadQuotaSize(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UploadQuotaSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::Telemetry
{
    inline auto PlatformTelemetryClient::Register(param::hstring const& id)
    {
        return impl::call_factory<PlatformTelemetryClient, IPlatformTelemetryClientStatics>([&](IPlatformTelemetryClientStatics const& f) { return f.Register(id); });
    }
    inline auto PlatformTelemetryClient::Register(param::hstring const& id, winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings const& settings)
    {
        return impl::call_factory<PlatformTelemetryClient, IPlatformTelemetryClientStatics>([&](IPlatformTelemetryClientStatics const& f) { return f.Register(id, settings); });
    }
    inline PlatformTelemetryRegistrationSettings::PlatformTelemetryRegistrationSettings() :
        PlatformTelemetryRegistrationSettings(impl::call_factory_cast<PlatformTelemetryRegistrationSettings(*)(winrt::Windows::Foundation::IActivationFactory const&), PlatformTelemetryRegistrationSettings>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PlatformTelemetryRegistrationSettings>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryClientStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::IPlatformTelemetryRegistrationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryClient> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::System::Diagnostics::Telemetry::PlatformTelemetryRegistrationSettings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
