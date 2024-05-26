// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_I2c_Provider_H
#define WINRT_Windows_Devices_I2c_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.I2c.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.I2c.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider) consume_Windows_Devices_I2c_Provider_II2cControllerProvider<D>::GetDeviceProvider(winrt::Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings const& settings) const
    {
        void* device{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cControllerProvider)->GetDeviceProvider(*(void**)(&settings), &device));
        return winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider{ device, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::Write(array_view<uint8_t const> buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider)->Write(buffer.size(), get_abi(buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult) consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::WritePartial(array_view<uint8_t const> buffer) const
    {
        winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider)->WritePartial(buffer.size(), get_abi(buffer), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::Read(array_view<uint8_t> buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider)->Read(buffer.size(), put_abi(buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult) consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::ReadPartial(array_view<uint8_t> buffer) const
    {
        winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider)->ReadPartial(buffer.size(), put_abi(buffer), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::WriteRead(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider)->WriteRead(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), put_abi(readBuffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult) consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::WriteReadPartial(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
    {
        winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider)->WriteReadPartial(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), put_abi(readBuffer), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider>>) consume_Windows_Devices_I2c_Provider_II2cProvider<D>::GetControllersAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::II2cProvider)->GetControllersAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider>>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SlaveAddress() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->get_SlaveAddress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SlaveAddress(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->put_SlaveAddress(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::Provider::ProviderI2cBusSpeed) consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::BusSpeed() const
    {
        winrt::Windows::Devices::I2c::Provider::ProviderI2cBusSpeed value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->get_BusSpeed(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::BusSpeed(winrt::Windows::Devices::I2c::Provider::ProviderI2cBusSpeed const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->put_BusSpeed(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::I2c::Provider::ProviderI2cSharingMode) consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SharingMode() const
    {
        winrt::Windows::Devices::I2c::Provider::ProviderI2cSharingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->get_SharingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SharingMode(winrt::Windows::Devices::I2c::Provider::ProviderI2cSharingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->put_SharingMode(static_cast<int32_t>(value)));
    }
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::Provider::II2cControllerProvider> : produce_base<D, winrt::Windows::Devices::I2c::Provider::II2cControllerProvider>
    {
        int32_t __stdcall GetDeviceProvider(void* settings, void** device) noexcept final try
        {
            clear_abi(device);
            typename D::abi_guard guard(this->shim());
            *device = detach_from<winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider>(this->shim().GetDeviceProvider(*reinterpret_cast<winrt::Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider> : produce_base<D, winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Write(uint32_t __bufferSize, uint8_t* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Write(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WritePartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(this->shim().WritePartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Read(uint32_t __bufferSize, uint8_t* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Read(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadPartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(this->shim().ReadPartial(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteRead(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteRead(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteReadPartial(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept final try
        {
            zero_abi<winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(this->shim().WriteReadPartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::Provider::II2cProvider> : produce_base<D, winrt::Windows::Devices::I2c::Provider::II2cProvider>
    {
        int32_t __stdcall GetControllersAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider>>>(this->shim().GetControllersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings> : produce_base<D, winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings>
    {
        int32_t __stdcall get_SlaveAddress(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SlaveAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SlaveAddress(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SlaveAddress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BusSpeed(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::I2c::Provider::ProviderI2cBusSpeed>(this->shim().BusSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BusSpeed(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BusSpeed(*reinterpret_cast<winrt::Windows::Devices::I2c::Provider::ProviderI2cBusSpeed const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SharingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::I2c::Provider::ProviderI2cSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SharingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SharingMode(*reinterpret_cast<winrt::Windows::Devices::I2c::Provider::ProviderI2cSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::I2c::Provider
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::Provider::II2cProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
