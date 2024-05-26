// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Pwm_H
#define WINRT_Windows_Devices_Pwm_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Devices.Pwm.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Pwm.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Pwm_IPwmController<D>::PinCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmController)->get_PinCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_IPwmController<D>::ActualFrequency() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmController)->get_ActualFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_IPwmController<D>::SetDesiredFrequency(double desiredFrequency) const
    {
        double result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmController)->SetDesiredFrequency(desiredFrequency, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_IPwmController<D>::MinFrequency() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmController)->get_MinFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_IPwmController<D>::MaxFrequency() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmController)->get_MaxFrequency(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Pwm::PwmPin) consume_Windows_Devices_Pwm_IPwmController<D>::OpenPin(int32_t pinNumber) const
    {
        void* pin{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmController)->OpenPin(pinNumber, &pin));
        return winrt::Windows::Devices::Pwm::PwmPin{ pin, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Pwm::PwmController>>) consume_Windows_Devices_Pwm_IPwmControllerStatics<D>::GetControllersAsync(winrt::Windows::Devices::Pwm::Provider::IPwmProvider const& provider) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmControllerStatics)->GetControllersAsync(*(void**)(&provider), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Pwm::PwmController>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Pwm::PwmController>) consume_Windows_Devices_Pwm_IPwmControllerStatics2<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmControllerStatics2)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Pwm::PwmController>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Pwm_IPwmControllerStatics3<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmControllerStatics3)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Pwm_IPwmControllerStatics3<D>::GetDeviceSelector(param::hstring const& friendlyName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmControllerStatics3)->GetDeviceSelectorFromFriendlyName(*(void**)(&friendlyName), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Pwm::PwmController>) consume_Windows_Devices_Pwm_IPwmControllerStatics3<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmControllerStatics3)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Pwm::PwmController>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Pwm::PwmController) consume_Windows_Devices_Pwm_IPwmPin<D>::Controller() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->get_Controller(&value));
        return winrt::Windows::Devices::Pwm::PwmController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Pwm_IPwmPin<D>::GetActiveDutyCyclePercentage() const
    {
        double result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->GetActiveDutyCyclePercentage(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_IPwmPin<D>::SetActiveDutyCyclePercentage(double dutyCyclePercentage) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->SetActiveDutyCyclePercentage(dutyCyclePercentage));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Pwm::PwmPulsePolarity) consume_Windows_Devices_Pwm_IPwmPin<D>::Polarity() const
    {
        winrt::Windows::Devices::Pwm::PwmPulsePolarity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->get_Polarity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_IPwmPin<D>::Polarity(winrt::Windows::Devices::Pwm::PwmPulsePolarity const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->put_Polarity(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_IPwmPin<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Pwm_IPwmPin<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Pwm_IPwmPin<D>::IsStarted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Pwm::IPwmPin)->get_IsStarted(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Pwm::IPwmController> : produce_base<D, winrt::Windows::Devices::Pwm::IPwmController>
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
        int32_t __stdcall SetDesiredFrequency(double desiredFrequency, double* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<double>(this->shim().SetDesiredFrequency(desiredFrequency));
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
        int32_t __stdcall get_MaxFrequency(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenPin(int32_t pinNumber, void** pin) noexcept final try
        {
            clear_abi(pin);
            typename D::abi_guard guard(this->shim());
            *pin = detach_from<winrt::Windows::Devices::Pwm::PwmPin>(this->shim().OpenPin(pinNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Pwm::IPwmControllerStatics> : produce_base<D, winrt::Windows::Devices::Pwm::IPwmControllerStatics>
    {
        int32_t __stdcall GetControllersAsync(void* provider, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Pwm::PwmController>>>(this->shim().GetControllersAsync(*reinterpret_cast<winrt::Windows::Devices::Pwm::Provider::IPwmProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Pwm::IPwmControllerStatics2> : produce_base<D, winrt::Windows::Devices::Pwm::IPwmControllerStatics2>
    {
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Pwm::PwmController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Pwm::IPwmControllerStatics3> : produce_base<D, winrt::Windows::Devices::Pwm::IPwmControllerStatics3>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelectorFromFriendlyName(void* friendlyName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<hstring const*>(&friendlyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Pwm::PwmController>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Pwm::IPwmPin> : produce_base<D, winrt::Windows::Devices::Pwm::IPwmPin>
    {
        int32_t __stdcall get_Controller(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Pwm::PwmController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetActiveDutyCyclePercentage(double* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<double>(this->shim().GetActiveDutyCyclePercentage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetActiveDutyCyclePercentage(double dutyCyclePercentage) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetActiveDutyCyclePercentage(dutyCyclePercentage);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Polarity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Pwm::PwmPulsePolarity>(this->shim().Polarity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Polarity(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Polarity(*reinterpret_cast<winrt::Windows::Devices::Pwm::PwmPulsePolarity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsStarted(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsStarted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Pwm
{
    inline auto PwmController::GetControllersAsync(winrt::Windows::Devices::Pwm::Provider::IPwmProvider const& provider)
    {
        return impl::call_factory<PwmController, IPwmControllerStatics>([&](IPwmControllerStatics const& f) { return f.GetControllersAsync(provider); });
    }
    inline auto PwmController::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Pwm::PwmController>(*)(IPwmControllerStatics2 const&), PwmController, IPwmControllerStatics2>([](IPwmControllerStatics2 const& f) { return f.GetDefaultAsync(); });
    }
    inline auto PwmController::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IPwmControllerStatics3 const&), PwmController, IPwmControllerStatics3>([](IPwmControllerStatics3 const& f) { return f.GetDeviceSelector(); });
    }
    inline auto PwmController::GetDeviceSelector(param::hstring const& friendlyName)
    {
        return impl::call_factory<PwmController, IPwmControllerStatics3>([&](IPwmControllerStatics3 const& f) { return f.GetDeviceSelector(friendlyName); });
    }
    inline auto PwmController::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<PwmController, IPwmControllerStatics3>([&](IPwmControllerStatics3 const& f) { return f.FromIdAsync(deviceId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Pwm::IPwmController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Pwm::IPwmControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Pwm::IPwmControllerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Pwm::IPwmControllerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Pwm::IPwmPin> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Pwm::PwmController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Pwm::PwmPin> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
