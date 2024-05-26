// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Display_H
#define WINRT_Windows_Devices_Display_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Devices.Display.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Display_IDisplayMonitor<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Display_IDisplayMonitor<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::DisplayMonitorConnectionKind) consume_Windows_Devices_Display_IDisplayMonitor<D>::ConnectionKind() const
    {
        winrt::Windows::Devices::Display::DisplayMonitorConnectionKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_ConnectionKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind) consume_Windows_Devices_Display_IDisplayMonitor<D>::PhysicalConnector() const
    {
        winrt::Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_PhysicalConnector(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Display_IDisplayMonitor<D>::DisplayAdapterDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_DisplayAdapterDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DisplayAdapterId) consume_Windows_Devices_Display_IDisplayMonitor<D>::DisplayAdapterId() const
    {
        winrt::Windows::Graphics::DisplayAdapterId value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_DisplayAdapterId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Devices_Display_IDisplayMonitor<D>::DisplayAdapterTargetId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_DisplayAdapterTargetId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Display::DisplayMonitorUsageKind) consume_Windows_Devices_Display_IDisplayMonitor<D>::UsageKind() const
    {
        winrt::Windows::Devices::Display::DisplayMonitorUsageKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_UsageKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) consume_Windows_Devices_Display_IDisplayMonitor<D>::NativeResolutionInRawPixels() const
    {
        winrt::Windows::Graphics::SizeInt32 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_NativeResolutionInRawPixels(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Size>) consume_Windows_Devices_Display_IDisplayMonitor<D>::PhysicalSizeInInches() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_PhysicalSizeInInches(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Size>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Display_IDisplayMonitor<D>::RawDpiX() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_RawDpiX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Display_IDisplayMonitor<D>::RawDpiY() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_RawDpiY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Devices_Display_IDisplayMonitor<D>::RedPrimary() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_RedPrimary(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Devices_Display_IDisplayMonitor<D>::GreenPrimary() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_GreenPrimary(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Devices_Display_IDisplayMonitor<D>::BluePrimary() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_BluePrimary(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Devices_Display_IDisplayMonitor<D>::WhitePoint() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_WhitePoint(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Display_IDisplayMonitor<D>::MaxLuminanceInNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_MaxLuminanceInNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Display_IDisplayMonitor<D>::MinLuminanceInNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_MinLuminanceInNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Display_IDisplayMonitor<D>::MaxAverageFullFrameLuminanceInNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->get_MaxAverageFullFrameLuminanceInNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<uint8_t>) consume_Windows_Devices_Display_IDisplayMonitor<D>::GetDescriptor(winrt::Windows::Devices::Display::DisplayMonitorDescriptorKind const& descriptorKind) const
    {
        uint32_t result_impl_size{};
        uint8_t* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor)->GetDescriptor(static_cast<int32_t>(descriptorKind), &result_impl_size, &result));
        return com_array<uint8_t>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Display_IDisplayMonitor2<D>::IsDolbyVisionSupportedInHdrMode() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitor2)->get_IsDolbyVisionSupportedInHdrMode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Display_IDisplayMonitorStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitorStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Display::DisplayMonitor>) consume_Windows_Devices_Display_IDisplayMonitorStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitorStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Display::DisplayMonitor>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Display::DisplayMonitor>) consume_Windows_Devices_Display_IDisplayMonitorStatics<D>::FromInterfaceIdAsync(param::hstring const& deviceInterfaceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Display::IDisplayMonitorStatics)->FromInterfaceIdAsync(*(void**)(&deviceInterfaceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Display::DisplayMonitor>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::IDisplayMonitor> : produce_base<D, winrt::Windows::Devices::Display::IDisplayMonitor>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConnectionKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::DisplayMonitorConnectionKind>(this->shim().ConnectionKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhysicalConnector(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind>(this->shim().PhysicalConnector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayAdapterDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayAdapterDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayAdapterId(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::DisplayAdapterId>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DisplayAdapterId>(this->shim().DisplayAdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayAdapterTargetId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DisplayAdapterTargetId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UsageKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Display::DisplayMonitorUsageKind>(this->shim().UsageKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NativeResolutionInRawPixels(struct struct_Windows_Graphics_SizeInt32* value) noexcept final try
        {
            zero_abi<winrt::Windows::Graphics::SizeInt32>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::SizeInt32>(this->shim().NativeResolutionInRawPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhysicalSizeInInches(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Size>>(this->shim().PhysicalSizeInInches());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RawDpiX(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().RawDpiX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RawDpiY(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().RawDpiY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RedPrimary(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().RedPrimary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GreenPrimary(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().GreenPrimary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BluePrimary(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().BluePrimary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WhitePoint(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().WhitePoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxLuminanceInNits(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MaxLuminanceInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinLuminanceInNits(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MinLuminanceInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxAverageFullFrameLuminanceInNits(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MaxAverageFullFrameLuminanceInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDescriptor(int32_t descriptorKind, uint32_t* __resultSize, uint8_t** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetDescriptor(*reinterpret_cast<winrt::Windows::Devices::Display::DisplayMonitorDescriptorKind const*>(&descriptorKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::IDisplayMonitor2> : produce_base<D, winrt::Windows::Devices::Display::IDisplayMonitor2>
    {
        int32_t __stdcall get_IsDolbyVisionSupportedInHdrMode(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDolbyVisionSupportedInHdrMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Display::IDisplayMonitorStatics> : produce_base<D, winrt::Windows::Devices::Display::IDisplayMonitorStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Display::DisplayMonitor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromInterfaceIdAsync(void* deviceInterfaceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Display::DisplayMonitor>>(this->shim().FromInterfaceIdAsync(*reinterpret_cast<hstring const*>(&deviceInterfaceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Display
{
    inline auto DisplayMonitor::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IDisplayMonitorStatics const&), DisplayMonitor, IDisplayMonitorStatics>([](IDisplayMonitorStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto DisplayMonitor::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<DisplayMonitor, IDisplayMonitorStatics>([&](IDisplayMonitorStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto DisplayMonitor::FromInterfaceIdAsync(param::hstring const& deviceInterfaceId)
    {
        return impl::call_factory<DisplayMonitor, IDisplayMonitorStatics>([&](IDisplayMonitorStatics const& f) { return f.FromInterfaceIdAsync(deviceInterfaceId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Display::IDisplayMonitor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::IDisplayMonitor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::IDisplayMonitorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Display::DisplayMonitor> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
