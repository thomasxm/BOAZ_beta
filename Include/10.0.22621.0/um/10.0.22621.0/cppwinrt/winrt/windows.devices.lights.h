// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Lights_H
#define WINRT_Windows_Devices_Lights_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Devices.Lights.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Lights_ILamp<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Lights_ILamp<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILamp<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Devices_Lights_ILamp<D>::BrightnessLevel() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->get_BrightnessLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILamp<D>::BrightnessLevel(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->put_BrightnessLevel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Lights_ILamp<D>::IsColorSettable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->get_IsColorSettable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Lights_ILamp<D>::Color() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->get_Color(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILamp<D>::Color(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->put_Color(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Lights::Lamp, winrt::Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->add_AvailabilityChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged_revoker consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Lights::Lamp, winrt::Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AvailabilityChanged_revoker>(this, AvailabilityChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILamp)->remove_AvailabilityChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Lights_ILampArray<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Lights_ILampArray<D>::HardwareVendorId() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_HardwareVendorId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Lights_ILampArray<D>::HardwareProductId() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_HardwareProductId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Lights_ILampArray<D>::HardwareVersion() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_HardwareVersion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Lights::LampArrayKind) consume_Windows_Devices_Lights_ILampArray<D>::LampArrayKind() const
    {
        winrt::Windows::Devices::Lights::LampArrayKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_LampArrayKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Lights_ILampArray<D>::LampCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_LampCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Lights_ILampArray<D>::MinUpdateInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_MinUpdateInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Devices_Lights_ILampArray<D>::BoundingBox() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_BoundingBox(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Lights_ILampArray<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Lights_ILampArray<D>::BrightnessLevel() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_BrightnessLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::BrightnessLevel(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->put_BrightnessLevel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Lights_ILampArray<D>::IsConnected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_IsConnected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Lights_ILampArray<D>::SupportsVirtualKeys() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->get_SupportsVirtualKeys(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Lights::LampInfo) consume_Windows_Devices_Lights_ILampArray<D>::GetLampInfo(int32_t lampIndex) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->GetLampInfo(lampIndex, &result));
        return winrt::Windows::Devices::Lights::LampInfo{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<int32_t>) consume_Windows_Devices_Lights_ILampArray<D>::GetIndicesForKey(winrt::Windows::System::VirtualKey const& key) const
    {
        uint32_t result_impl_size{};
        int32_t* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->GetIndicesForKey(static_cast<int32_t>(key), &result_impl_size, &result));
        return com_array<int32_t>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<int32_t>) consume_Windows_Devices_Lights_ILampArray<D>::GetIndicesForPurposes(winrt::Windows::Devices::Lights::LampPurposes const& purposes) const
    {
        uint32_t result_impl_size{};
        int32_t* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->GetIndicesForPurposes(static_cast<uint32_t>(purposes), &result_impl_size, &result));
        return com_array<int32_t>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::SetColor(winrt::Windows::UI::Color const& desiredColor) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SetColor(impl::bind_in(desiredColor)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::SetColorForIndex(int32_t lampIndex, winrt::Windows::UI::Color const& desiredColor) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SetColorForIndex(lampIndex, impl::bind_in(desiredColor)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::SetSingleColorForIndices(winrt::Windows::UI::Color const& desiredColor, array_view<int32_t const> lampIndexes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SetSingleColorForIndices(impl::bind_in(desiredColor), lampIndexes.size(), get_abi(lampIndexes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForIndices(array_view<winrt::Windows::UI::Color const> desiredColors, array_view<int32_t const> lampIndexes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SetColorsForIndices(desiredColors.size(), get_abi(desiredColors), lampIndexes.size(), get_abi(lampIndexes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForKey(winrt::Windows::UI::Color const& desiredColor, winrt::Windows::System::VirtualKey const& key) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SetColorsForKey(impl::bind_in(desiredColor), static_cast<int32_t>(key)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForKeys(array_view<winrt::Windows::UI::Color const> desiredColors, array_view<winrt::Windows::System::VirtualKey const> keys) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SetColorsForKeys(desiredColors.size(), get_abi(desiredColors), keys.size(), get_abi(keys)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForPurposes(winrt::Windows::UI::Color const& desiredColor, winrt::Windows::Devices::Lights::LampPurposes const& purposes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SetColorsForPurposes(impl::bind_in(desiredColor), static_cast<uint32_t>(purposes)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Devices_Lights_ILampArray<D>::SendMessageAsync(int32_t messageId, winrt::Windows::Storage::Streams::IBuffer const& message) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->SendMessageAsync(messageId, *(void**)(&message), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_Lights_ILampArray<D>::RequestMessageAsync(int32_t messageId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray)->RequestMessageAsync(messageId, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Lights_ILampArray2<D>::IsAvailable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray2)->get_IsAvailable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Lights_ILampArray2<D>::AvailabilityChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Lights::LampArray, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray2)->add_AvailabilityChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Lights_ILampArray2<D>::AvailabilityChanged_revoker consume_Windows_Devices_Lights_ILampArray2<D>::AvailabilityChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Lights::LampArray, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AvailabilityChanged_revoker>(this, AvailabilityChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Lights_ILampArray2<D>::AvailabilityChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArray2)->remove_AvailabilityChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Lights_ILampArrayStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArrayStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::LampArray>) consume_Windows_Devices_Lights_ILampArrayStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampArrayStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::LampArray>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Lights_ILampAvailabilityChangedEventArgs<D>::IsAvailable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs)->get_IsAvailable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Lights_ILampInfo<D>::Index() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_Index(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Lights::LampPurposes) consume_Windows_Devices_Lights_ILampInfo<D>::Purposes() const
    {
        winrt::Windows::Devices::Lights::LampPurposes value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_Purposes(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Devices_Lights_ILampInfo<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Lights_ILampInfo<D>::RedLevelCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_RedLevelCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Lights_ILampInfo<D>::GreenLevelCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_GreenLevelCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Lights_ILampInfo<D>::BlueLevelCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_BlueLevelCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Lights_ILampInfo<D>::GainLevelCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_GainLevelCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) consume_Windows_Devices_Lights_ILampInfo<D>::FixedColor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_FixedColor(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Devices_Lights_ILampInfo<D>::GetNearestSupportedColor(winrt::Windows::UI::Color const& desiredColor) const
    {
        winrt::Windows::UI::Color result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->GetNearestSupportedColor(impl::bind_in(desiredColor), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Lights_ILampInfo<D>::UpdateLatency() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampInfo)->get_UpdateLatency(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Lights_ILampStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::Lamp>) consume_Windows_Devices_Lights_ILampStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::Lamp>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::Lamp>) consume_Windows_Devices_Lights_ILampStatics<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Lights::ILampStatics)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::Lamp>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Lights::ILamp> : produce_base<D, winrt::Windows::Devices::Lights::ILamp>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BrightnessLevel(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().BrightnessLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BrightnessLevel(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BrightnessLevel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsColorSettable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsColorSettable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Color(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Color(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Color(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AvailabilityChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AvailabilityChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Lights::Lamp, winrt::Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AvailabilityChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AvailabilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Lights::ILampArray> : produce_base<D, winrt::Windows::Devices::Lights::ILampArray>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HardwareVendorId(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().HardwareVendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HardwareProductId(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().HardwareProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HardwareVersion(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().HardwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LampArrayKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Lights::LampArrayKind>(this->shim().LampArrayKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LampCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LampCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinUpdateInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().MinUpdateInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BoundingBox(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BrightnessLevel(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().BrightnessLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BrightnessLevel(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BrightnessLevel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsConnected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConnected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportsVirtualKeys(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SupportsVirtualKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLampInfo(int32_t lampIndex, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Lights::LampInfo>(this->shim().GetLampInfo(lampIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIndicesForKey(int32_t key, uint32_t* __resultSize, int32_t** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetIndicesForKey(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&key)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIndicesForPurposes(uint32_t purposes, uint32_t* __resultSize, int32_t** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetIndicesForPurposes(*reinterpret_cast<winrt::Windows::Devices::Lights::LampPurposes const*>(&purposes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetColor(struct struct_Windows_UI_Color desiredColor) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&desiredColor));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetColorForIndex(int32_t lampIndex, struct struct_Windows_UI_Color desiredColor) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetColorForIndex(lampIndex, *reinterpret_cast<winrt::Windows::UI::Color const*>(&desiredColor));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSingleColorForIndices(struct struct_Windows_UI_Color desiredColor, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSingleColorForIndices(*reinterpret_cast<winrt::Windows::UI::Color const*>(&desiredColor), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetColorsForIndices(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetColorsForIndices(array_view<winrt::Windows::UI::Color const>(reinterpret_cast<winrt::Windows::UI::Color const *>(desiredColors), reinterpret_cast<winrt::Windows::UI::Color const *>(desiredColors) + __desiredColorsSize), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetColorsForKey(struct struct_Windows_UI_Color desiredColor, int32_t key) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetColorsForKey(*reinterpret_cast<winrt::Windows::UI::Color const*>(&desiredColor), *reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&key));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetColorsForKeys(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __keysSize, int32_t* keys) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetColorsForKeys(array_view<winrt::Windows::UI::Color const>(reinterpret_cast<winrt::Windows::UI::Color const *>(desiredColors), reinterpret_cast<winrt::Windows::UI::Color const *>(desiredColors) + __desiredColorsSize), array_view<winrt::Windows::System::VirtualKey const>(reinterpret_cast<winrt::Windows::System::VirtualKey const *>(keys), reinterpret_cast<winrt::Windows::System::VirtualKey const *>(keys) + __keysSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetColorsForPurposes(struct struct_Windows_UI_Color desiredColor, uint32_t purposes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetColorsForPurposes(*reinterpret_cast<winrt::Windows::UI::Color const*>(&desiredColor), *reinterpret_cast<winrt::Windows::Devices::Lights::LampPurposes const*>(&purposes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendMessageAsync(int32_t messageId, void* message, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(messageId, *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestMessageAsync(int32_t messageId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().RequestMessageAsync(messageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Lights::ILampArray2> : produce_base<D, winrt::Windows::Devices::Lights::ILampArray2>
    {
        int32_t __stdcall get_IsAvailable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AvailabilityChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AvailabilityChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Lights::LampArray, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AvailabilityChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AvailabilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Lights::ILampArrayStatics> : produce_base<D, winrt::Windows::Devices::Lights::ILampArrayStatics>
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
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::LampArray>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs>
    {
        int32_t __stdcall get_IsAvailable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Lights::ILampInfo> : produce_base<D, winrt::Windows::Devices::Lights::ILampInfo>
    {
        int32_t __stdcall get_Index(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Index());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Purposes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Lights::LampPurposes>(this->shim().Purposes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RedLevelCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RedLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GreenLevelCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().GreenLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BlueLevelCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().BlueLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GainLevelCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().GainLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FixedColor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>>(this->shim().FixedColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNearestSupportedColor(struct struct_Windows_UI_Color desiredColor, struct struct_Windows_UI_Color* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Color>(this->shim().GetNearestSupportedColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&desiredColor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpdateLatency(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().UpdateLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Lights::ILampStatics> : produce_base<D, winrt::Windows::Devices::Lights::ILampStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::Lamp>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::Lamp>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Lights
{
    constexpr auto operator|(LampPurposes const left, LampPurposes const right) noexcept
    {
        return static_cast<LampPurposes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(LampPurposes& left, LampPurposes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(LampPurposes const left, LampPurposes const right) noexcept
    {
        return static_cast<LampPurposes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(LampPurposes& left, LampPurposes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(LampPurposes const value) noexcept
    {
        return static_cast<LampPurposes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(LampPurposes const left, LampPurposes const right) noexcept
    {
        return static_cast<LampPurposes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(LampPurposes& left, LampPurposes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto Lamp::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ILampStatics const&), Lamp, ILampStatics>([](ILampStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto Lamp::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Lamp, ILampStatics>([&](ILampStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Lamp::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Lights::Lamp>(*)(ILampStatics const&), Lamp, ILampStatics>([](ILampStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto LampArray::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(ILampArrayStatics const&), LampArray, ILampArrayStatics>([](ILampArrayStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto LampArray::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<LampArray, ILampArrayStatics>([&](ILampArrayStatics const& f) { return f.FromIdAsync(deviceId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Lights::ILamp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::ILampArray> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::ILampArray2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::ILampArrayStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::ILampInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::ILampStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::Lamp> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::LampArray> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::LampAvailabilityChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Lights::LampInfo> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
