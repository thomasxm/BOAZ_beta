// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Gpio_H
#define WINRT_Windows_Devices_Gpio_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Devices.Gpio.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Gpio.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Polarity(winrt::Windows::Devices::Gpio::GpioChangePolarity const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounter)->put_Polarity(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangePolarity) consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Polarity() const
    {
        winrt::Windows::Devices::Gpio::GpioChangePolarity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounter)->get_Polarity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::IsStarted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounter)->get_IsStarted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounter)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounter)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangeCount) consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Read() const
    {
        winrt::Windows::Devices::Gpio::GpioChangeCount value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounter)->Read(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangeCount) consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Reset() const
    {
        winrt::Windows::Devices::Gpio::GpioChangeCount value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounter)->Reset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangeCounter) consume_Windows_Devices_Gpio_IGpioChangeCounterFactory<D>::Create(winrt::Windows::Devices::Gpio::GpioPin const& pin) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeCounterFactory)->Create(*(void**)(&pin), &value));
        return winrt::Windows::Devices::Gpio::GpioChangeCounter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Capacity() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->get_Capacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Length() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->get_Length(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::IsEmpty() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->get_IsEmpty(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::IsOverflowed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->get_IsOverflowed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Polarity(winrt::Windows::Devices::Gpio::GpioChangePolarity const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->put_Polarity(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangePolarity) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Polarity() const
    {
        winrt::Windows::Devices::Gpio::GpioChangePolarity value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->get_Polarity(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::IsStarted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->get_IsStarted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangeRecord) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::GetNextItem() const
    {
        winrt::Windows::Devices::Gpio::GpioChangeRecord value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->GetNextItem(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangeRecord) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::PeekNextItem() const
    {
        winrt::Windows::Devices::Gpio::GpioChangeRecord value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->PeekNextItem(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Gpio::GpioChangeRecord>) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::GetAllItems() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->GetAllItems(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Gpio::GpioChangeRecord>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_Gpio_IGpioChangeReader<D>::WaitForItemsAsync(int32_t count) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReader)->WaitForItemsAsync(count, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangeReader) consume_Windows_Devices_Gpio_IGpioChangeReaderFactory<D>::Create(winrt::Windows::Devices::Gpio::GpioPin const& pin) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReaderFactory)->Create(*(void**)(&pin), &value));
        return winrt::Windows::Devices::Gpio::GpioChangeReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioChangeReader) consume_Windows_Devices_Gpio_IGpioChangeReaderFactory<D>::CreateWithCapacity(winrt::Windows::Devices::Gpio::GpioPin const& pin, int32_t minCapacity) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioChangeReaderFactory)->CreateWithCapacity(*(void**)(&pin), minCapacity, &value));
        return winrt::Windows::Devices::Gpio::GpioChangeReader{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Gpio_IGpioController<D>::PinCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioController)->get_PinCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioPin) consume_Windows_Devices_Gpio_IGpioController<D>::OpenPin(int32_t pinNumber) const
    {
        void* pin{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioController)->OpenPin(pinNumber, &pin));
        return winrt::Windows::Devices::Gpio::GpioPin{ pin, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioPin) consume_Windows_Devices_Gpio_IGpioController<D>::OpenPin(int32_t pinNumber, winrt::Windows::Devices::Gpio::GpioSharingMode const& sharingMode) const
    {
        void* pin{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioController)->OpenPinWithSharingMode(pinNumber, static_cast<int32_t>(sharingMode), &pin));
        return winrt::Windows::Devices::Gpio::GpioPin{ pin, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Gpio_IGpioController<D>::TryOpenPin(int32_t pinNumber, winrt::Windows::Devices::Gpio::GpioSharingMode const& sharingMode, winrt::Windows::Devices::Gpio::GpioPin& pin, winrt::Windows::Devices::Gpio::GpioOpenStatus& openStatus) const
    {
        bool succeeded{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioController)->TryOpenPin(pinNumber, static_cast<int32_t>(sharingMode), impl::bind_out(pin), reinterpret_cast<int32_t*>(&openStatus), &succeeded));
        return succeeded;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioController) consume_Windows_Devices_Gpio_IGpioControllerStatics<D>::GetDefault() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioControllerStatics)->GetDefault(&value));
        return winrt::Windows::Devices::Gpio::GpioController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Gpio::GpioController>>) consume_Windows_Devices_Gpio_IGpioControllerStatics2<D>::GetControllersAsync(winrt::Windows::Devices::Gpio::Provider::IGpioProvider const& provider) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioControllerStatics2)->GetControllersAsync(*(void**)(&provider), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Gpio::GpioController>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Gpio::GpioController>) consume_Windows_Devices_Gpio_IGpioControllerStatics2<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioControllerStatics2)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Gpio::GpioController>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Gpio::GpioPin, winrt::Windows::Devices::Gpio::GpioPinValueChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->add_ValueChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged_revoker consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Gpio::GpioPin, winrt::Windows::Devices::Gpio::GpioPinValueChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ValueChanged_revoker>(this, ValueChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->remove_ValueChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Gpio_IGpioPin<D>::DebounceTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->get_DebounceTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioPin<D>::DebounceTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->put_DebounceTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Gpio_IGpioPin<D>::PinNumber() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->get_PinNumber(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioSharingMode) consume_Windows_Devices_Gpio_IGpioPin<D>::SharingMode() const
    {
        winrt::Windows::Devices::Gpio::GpioSharingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->get_SharingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Gpio_IGpioPin<D>::IsDriveModeSupported(winrt::Windows::Devices::Gpio::GpioPinDriveMode const& driveMode) const
    {
        bool supported{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->IsDriveModeSupported(static_cast<int32_t>(driveMode), &supported));
        return supported;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioPinDriveMode) consume_Windows_Devices_Gpio_IGpioPin<D>::GetDriveMode() const
    {
        winrt::Windows::Devices::Gpio::GpioPinDriveMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->GetDriveMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioPin<D>::SetDriveMode(winrt::Windows::Devices::Gpio::GpioPinDriveMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->SetDriveMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Gpio_IGpioPin<D>::Write(winrt::Windows::Devices::Gpio::GpioPinValue const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->Write(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioPinValue) consume_Windows_Devices_Gpio_IGpioPin<D>::Read() const
    {
        winrt::Windows::Devices::Gpio::GpioPinValue value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPin)->Read(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Gpio::GpioPinEdge) consume_Windows_Devices_Gpio_IGpioPinValueChangedEventArgs<D>::Edge() const
    {
        winrt::Windows::Devices::Gpio::GpioPinEdge value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs)->get_Edge(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioChangeCounter> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioChangeCounter>
    {
        int32_t __stdcall put_Polarity(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Polarity(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioChangePolarity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Polarity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangePolarity>(this->shim().Polarity());
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
        int32_t __stdcall Read(struct struct_Windows_Devices_Gpio_GpioChangeCount* value) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::Gpio::GpioChangeCount>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangeCount>(this->shim().Read());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Reset(struct struct_Windows_Devices_Gpio_GpioChangeCount* value) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::Gpio::GpioChangeCount>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangeCount>(this->shim().Reset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioChangeCounterFactory> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioChangeCounterFactory>
    {
        int32_t __stdcall Create(void* pin, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangeCounter>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioPin const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioChangeReader> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioChangeReader>
    {
        int32_t __stdcall get_Capacity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Capacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Length(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEmpty(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOverflowed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOverflowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Polarity(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Polarity(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioChangePolarity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Polarity(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangePolarity>(this->shim().Polarity());
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
        int32_t __stdcall Clear() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNextItem(struct struct_Windows_Devices_Gpio_GpioChangeRecord* value) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::Gpio::GpioChangeRecord>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangeRecord>(this->shim().GetNextItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PeekNextItem(struct struct_Windows_Devices_Gpio_GpioChangeRecord* value) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::Gpio::GpioChangeRecord>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangeRecord>(this->shim().PeekNextItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAllItems(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Gpio::GpioChangeRecord>>(this->shim().GetAllItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WaitForItemsAsync(int32_t count, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().WaitForItemsAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioChangeReaderFactory> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioChangeReaderFactory>
    {
        int32_t __stdcall Create(void* pin, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangeReader>(this->shim().Create(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioPin const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithCapacity(void* pin, int32_t minCapacity, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioChangeReader>(this->shim().CreateWithCapacity(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioPin const*>(&pin), minCapacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioController> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioController>
    {
        int32_t __stdcall get_PinCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PinCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenPin(int32_t pinNumber, void** pin) noexcept final try
        {
            clear_abi(pin);
            typename D::abi_guard guard(this->shim());
            *pin = detach_from<winrt::Windows::Devices::Gpio::GpioPin>(this->shim().OpenPin(pinNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenPinWithSharingMode(int32_t pinNumber, int32_t sharingMode, void** pin) noexcept final try
        {
            clear_abi(pin);
            typename D::abi_guard guard(this->shim());
            *pin = detach_from<winrt::Windows::Devices::Gpio::GpioPin>(this->shim().OpenPin(pinNumber, *reinterpret_cast<winrt::Windows::Devices::Gpio::GpioSharingMode const*>(&sharingMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryOpenPin(int32_t pinNumber, int32_t sharingMode, void** pin, int32_t* openStatus, bool* succeeded) noexcept final try
        {
            clear_abi(pin);
            typename D::abi_guard guard(this->shim());
            *succeeded = detach_from<bool>(this->shim().TryOpenPin(pinNumber, *reinterpret_cast<winrt::Windows::Devices::Gpio::GpioSharingMode const*>(&sharingMode), *reinterpret_cast<winrt::Windows::Devices::Gpio::GpioPin*>(pin), *reinterpret_cast<winrt::Windows::Devices::Gpio::GpioOpenStatus*>(openStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioControllerStatics> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioControllerStatics>
    {
        int32_t __stdcall GetDefault(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioController>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioControllerStatics2> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioControllerStatics2>
    {
        int32_t __stdcall GetControllersAsync(void* provider, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Gpio::GpioController>>>(this->shim().GetControllersAsync(*reinterpret_cast<winrt::Windows::Devices::Gpio::Provider::IGpioProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Gpio::GpioController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioPin> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioPin>
    {
        int32_t __stdcall add_ValueChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ValueChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Gpio::GpioPin, winrt::Windows::Devices::Gpio::GpioPinValueChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ValueChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ValueChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_DebounceTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DebounceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DebounceTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DebounceTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PinNumber(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PinNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsDriveModeSupported(int32_t driveMode, bool* supported) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *supported = detach_from<bool>(this->shim().IsDriveModeSupported(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioPinDriveMode const*>(&driveMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDriveMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioPinDriveMode>(this->shim().GetDriveMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDriveMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDriveMode(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioPinDriveMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Write(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Write(*reinterpret_cast<winrt::Windows::Devices::Gpio::GpioPinValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Read(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioPinValue>(this->shim().Read());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs>
    {
        int32_t __stdcall get_Edge(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Gpio::GpioPinEdge>(this->shim().Edge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Gpio
{
    inline GpioChangeCounter::GpioChangeCounter(winrt::Windows::Devices::Gpio::GpioPin const& pin) :
        GpioChangeCounter(impl::call_factory<GpioChangeCounter, IGpioChangeCounterFactory>([&](IGpioChangeCounterFactory const& f) { return f.Create(pin); }))
    {
    }
    inline GpioChangeReader::GpioChangeReader(winrt::Windows::Devices::Gpio::GpioPin const& pin) :
        GpioChangeReader(impl::call_factory<GpioChangeReader, IGpioChangeReaderFactory>([&](IGpioChangeReaderFactory const& f) { return f.Create(pin); }))
    {
    }
    inline GpioChangeReader::GpioChangeReader(winrt::Windows::Devices::Gpio::GpioPin const& pin, int32_t minCapacity) :
        GpioChangeReader(impl::call_factory<GpioChangeReader, IGpioChangeReaderFactory>([&](IGpioChangeReaderFactory const& f) { return f.CreateWithCapacity(pin, minCapacity); }))
    {
    }
    inline auto GpioController::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Gpio::GpioController(*)(IGpioControllerStatics const&), GpioController, IGpioControllerStatics>([](IGpioControllerStatics const& f) { return f.GetDefault(); });
    }
    inline auto GpioController::GetControllersAsync(winrt::Windows::Devices::Gpio::Provider::IGpioProvider const& provider)
    {
        return impl::call_factory<GpioController, IGpioControllerStatics2>([&](IGpioControllerStatics2 const& f) { return f.GetControllersAsync(provider); });
    }
    inline auto GpioController::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Gpio::GpioController>(*)(IGpioControllerStatics2 const&), GpioController, IGpioControllerStatics2>([](IGpioControllerStatics2 const& f) { return f.GetDefaultAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeCounter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeCounterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeReaderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioControllerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioPin> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::GpioChangeCounter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::GpioChangeReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::GpioController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::GpioPin> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Gpio::GpioPinValueChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
