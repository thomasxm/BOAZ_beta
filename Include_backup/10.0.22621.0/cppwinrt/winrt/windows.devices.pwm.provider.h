// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Pwm_Provider_H
#define WINRT_Windows_Devices_Pwm_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Pwm.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Pwm.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::PinCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->get_PinCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::ActualFrequency() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->get_ActualFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::SetDesiredFrequency(double frequency) const
    {
        double result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->SetDesiredFrequency(frequency, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::MaxFrequency() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->get_MaxFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::MinFrequency() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->get_MinFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::AcquirePin(int32_t pin) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->AcquirePin(pin));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::ReleasePin(int32_t pin) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->ReleasePin(pin));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::EnablePin(int32_t pin) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->EnablePin(pin));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::DisablePin(int32_t pin) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->DisablePin(pin));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_Provider_IPwmControllerProvider<D>::SetPulseParameters(int32_t pin, double dutyCycle, bool invertPolarity) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider)->SetPulseParameters(pin, dutyCycle, invertPolarity));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider>) consume_Windows_Devices_Pwm_Provider_IPwmProvider<D>::GetControllers() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::Provider::IPwmProvider)->GetControllers(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider>{ result, take_ownership_from_abi };
    }
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider> : produce_base<D, winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider>
    {
        int32_t __stdcall get_PinCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PinCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActualFrequency(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ActualFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDesiredFrequency(double frequency, double* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<double>(this->shim().SetDesiredFrequency(frequency));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxFrequency(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinFrequency(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AcquirePin(int32_t pin) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcquirePin(pin);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReleasePin(int32_t pin) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleasePin(pin);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnablePin(int32_t pin) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnablePin(pin);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisablePin(int32_t pin) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisablePin(pin);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPulseParameters(int32_t pin, double dutyCycle, bool invertPolarity) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPulseParameters(pin, dutyCycle, invertPolarity);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Pwm::Provider::IPwmProvider> : produce_base<D, winrt::Windows::Devices::Pwm::Provider::IPwmProvider>
    {
        int32_t __stdcall GetControllers(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider>>(this->shim().GetControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Devices::Pwm::Provider
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Pwm::Provider::IPwmControllerProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Pwm::Provider::IPwmProvider> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
