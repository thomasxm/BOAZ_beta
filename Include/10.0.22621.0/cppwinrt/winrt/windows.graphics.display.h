// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Display_H
#define WINRT_Windows_Graphics_Display_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Graphics.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Graphics.Display.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::AdvancedColorKind) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::CurrentAdvancedColorKind() const
    {
        winrt::Windows::Graphics::Display::AdvancedColorKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_CurrentAdvancedColorKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::RedPrimary() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_RedPrimary(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::GreenPrimary() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_GreenPrimary(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::BluePrimary() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_BluePrimary(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::WhitePoint() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_WhitePoint(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::MaxLuminanceInNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_MaxLuminanceInNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::MinLuminanceInNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_MinLuminanceInNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::MaxAverageFullFrameLuminanceInNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_MaxAverageFullFrameLuminanceInNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::SdrWhiteLevelInNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->get_SdrWhiteLevelInNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::IsHdrMetadataFormatCurrentlySupported(winrt::Windows::Graphics::Display::HdrMetadataFormat const& format) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->IsHdrMetadataFormatCurrentlySupported(static_cast<int32_t>(format), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IAdvancedColorInfo<D>::IsAdvancedColorKindAvailable(winrt::Windows::Graphics::Display::AdvancedColorKind const& kind) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IAdvancedColorInfo)->IsAdvancedColorKindAvailable(static_cast<int32_t>(kind), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->get_IsSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->get_IsOverrideActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevel() const
    {
        double level{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->get_BrightnessLevel(&level));
        return level;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IBrightnessOverride<D>::SetBrightnessLevel(double brightnessLevel, winrt::Windows::Graphics::Display::DisplayBrightnessOverrideOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->SetBrightnessLevel(brightnessLevel, static_cast<uint32_t>(options)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IBrightnessOverride<D>::SetBrightnessScenario(winrt::Windows::Graphics::Display::DisplayBrightnessScenario const& scenario, winrt::Windows::Graphics::Display::DisplayBrightnessOverrideOptions const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->SetBrightnessScenario(static_cast<int32_t>(scenario), static_cast<uint32_t>(options)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Graphics_Display_IBrightnessOverride<D>::GetLevelForScenario(winrt::Windows::Graphics::Display::DisplayBrightnessScenario const& scenario) const
    {
        double brightnessLevel{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->GetLevelForScenario(static_cast<int32_t>(scenario), &brightnessLevel));
        return brightnessLevel;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IBrightnessOverride<D>::StartOverride() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->StartOverride());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IBrightnessOverride<D>::StopOverride() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->StopOverride());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->add_IsSupportedChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged_revoker consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsSupportedChanged_revoker>(this, IsSupportedChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsSupportedChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->remove_IsSupportedChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->add_IsOverrideActiveChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged_revoker consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsOverrideActiveChanged_revoker>(this, IsOverrideActiveChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IBrightnessOverride<D>::IsOverrideActiveChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->remove_IsOverrideActiveChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->add_BrightnessLevelChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged_revoker consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, BrightnessLevelChanged_revoker>(this, BrightnessLevelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IBrightnessOverride<D>::BrightnessLevelChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverride)->remove_BrightnessLevelChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Graphics_Display_IBrightnessOverrideSettings<D>::DesiredLevel() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideSettings)->get_DesiredLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IBrightnessOverrideSettings<D>::DesiredNits() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideSettings)->get_DesiredNits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::BrightnessOverrideSettings) consume_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics<D>::CreateFromLevel(double level) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics)->CreateFromLevel(level, &result));
        return winrt::Windows::Graphics::Display::BrightnessOverrideSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::BrightnessOverrideSettings) consume_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics<D>::CreateFromNits(float nits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics)->CreateFromNits(nits, &result));
        return winrt::Windows::Graphics::Display::BrightnessOverrideSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::BrightnessOverrideSettings) consume_Windows_Graphics_Display_IBrightnessOverrideSettingsStatics<D>::CreateFromDisplayBrightnessOverrideScenario(winrt::Windows::Graphics::Display::DisplayBrightnessOverrideScenario const& overrideScenario) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics)->CreateFromDisplayBrightnessOverrideScenario(static_cast<int32_t>(overrideScenario), &result));
        return winrt::Windows::Graphics::Display::BrightnessOverrideSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::BrightnessOverride) consume_Windows_Graphics_Display_IBrightnessOverrideStatics<D>::GetDefaultForSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideStatics)->GetDefaultForSystem(&value));
        return winrt::Windows::Graphics::Display::BrightnessOverride{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::BrightnessOverride) consume_Windows_Graphics_Display_IBrightnessOverrideStatics<D>::GetForCurrentView() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideStatics)->GetForCurrentView(&value));
        return winrt::Windows::Graphics::Display::BrightnessOverride{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Graphics_Display_IBrightnessOverrideStatics<D>::SaveForSystemAsync(winrt::Windows::Graphics::Display::BrightnessOverride const& value) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IBrightnessOverrideStatics)->SaveForSystemAsync(*(void**)(&value), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayColorOverrideScenario) consume_Windows_Graphics_Display_IColorOverrideSettings<D>::DesiredDisplayColorOverrideScenario() const
    {
        winrt::Windows::Graphics::Display::DisplayColorOverrideScenario value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IColorOverrideSettings)->get_DesiredDisplayColorOverrideScenario(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::ColorOverrideSettings) consume_Windows_Graphics_Display_IColorOverrideSettingsStatics<D>::CreateFromDisplayColorOverrideScenario(winrt::Windows::Graphics::Display::DisplayColorOverrideScenario const& overrideScenario) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IColorOverrideSettingsStatics)->CreateFromDisplayColorOverrideScenario(static_cast<int32_t>(overrideScenario), &result));
        return winrt::Windows::Graphics::Display::ColorOverrideSettings{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::ColorOverrideSettings) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::ColorOverrideSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->get_ColorOverrideSettings(&value));
        return winrt::Windows::Graphics::Display::ColorOverrideSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::ColorOverrideSettings(winrt::Windows::Graphics::Display::ColorOverrideSettings const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->put_ColorOverrideSettings(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::BrightnessOverrideSettings) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::BrightnessOverrideSettings() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->get_BrightnessOverrideSettings(&value));
        return winrt::Windows::Graphics::Display::BrightnessOverrideSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::BrightnessOverrideSettings(winrt::Windows::Graphics::Display::BrightnessOverrideSettings const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->put_BrightnessOverrideSettings(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverride() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->get_CanOverride(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->get_IsOverrideActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::GetCurrentDisplayEnhancementOverrideCapabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->GetCurrentDisplayEnhancementOverrideCapabilities(&value));
        return winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::RequestOverride() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->RequestOverride());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::StopOverride() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->StopOverride());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->add_CanOverrideChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged_revoker consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, CanOverrideChanged_revoker>(this, CanOverrideChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::CanOverrideChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->remove_CanOverrideChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->add_IsOverrideActiveChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged_revoker consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, IsOverrideActiveChanged_revoker>(this, IsOverrideActiveChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::IsOverrideActiveChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->remove_IsOverrideActiveChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->add_DisplayEnhancementOverrideCapabilitiesChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged_revoker consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, DisplayEnhancementOverrideCapabilitiesChanged_revoker>(this, DisplayEnhancementOverrideCapabilitiesChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayEnhancementOverride<D>::DisplayEnhancementOverrideCapabilitiesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverride)->remove_DisplayEnhancementOverrideCapabilitiesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities<D>::IsBrightnessControlSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities)->get_IsBrightnessControlSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities<D>::IsBrightnessNitsControlSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities)->get_IsBrightnessNitsControlSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Display::NitRange>) consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilities<D>::GetSupportedNitRanges() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities)->GetSupportedNitRanges(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Display::NitRange>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities) consume_Windows_Graphics_Display_IDisplayEnhancementOverrideCapabilitiesChangedEventArgs<D>::Capabilities() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs)->get_Capabilities(&value));
        return winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayEnhancementOverride) consume_Windows_Graphics_Display_IDisplayEnhancementOverrideStatics<D>::GetForCurrentView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideStatics)->GetForCurrentView(&result));
        return winrt::Windows::Graphics::Display::DisplayEnhancementOverride{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Graphics_Display_IDisplayInformation<D>::CurrentOrientation() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->get_CurrentOrientation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Graphics_Display_IDisplayInformation<D>::NativeOrientation() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->get_NativeOrientation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->add_OrientationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, OrientationChanged_revoker>(this, OrientationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayInformation<D>::OrientationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->remove_OrientationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::ResolutionScale) consume_Windows_Graphics_Display_IDisplayInformation<D>::ResolutionScale() const
    {
        winrt::Windows::Graphics::Display::ResolutionScale value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->get_ResolutionScale(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IDisplayInformation<D>::LogicalDpi() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->get_LogicalDpi(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IDisplayInformation<D>::RawDpiX() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->get_RawDpiX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IDisplayInformation<D>::RawDpiY() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->get_RawDpiY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->add_DpiChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DpiChanged_revoker>(this, DpiChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayInformation<D>::DpiChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->remove_DpiChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->get_StereoEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->add_StereoEnabledChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StereoEnabledChanged_revoker>(this, StereoEnabledChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayInformation<D>::StereoEnabledChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->remove_StereoEnabledChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Graphics_Display_IDisplayInformation<D>::GetColorProfileAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->GetColorProfileAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->add_ColorProfileChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ColorProfileChanged_revoker>(this, ColorProfileChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayInformation<D>::ColorProfileChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation)->remove_ColorProfileChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Graphics_Display_IDisplayInformation2<D>::RawPixelsPerViewPixel() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation2)->get_RawPixelsPerViewPixel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Graphics_Display_IDisplayInformation3<D>::DiagonalSizeInInches() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation3)->get_DiagonalSizeInInches(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Graphics_Display_IDisplayInformation4<D>::ScreenWidthInRawPixels() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation4)->get_ScreenWidthInRawPixels(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Graphics_Display_IDisplayInformation4<D>::ScreenHeightInRawPixels() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation4)->get_ScreenHeightInRawPixels(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::AdvancedColorInfo) consume_Windows_Graphics_Display_IDisplayInformation5<D>::GetAdvancedColorInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation5)->GetAdvancedColorInfo(&value));
        return winrt::Windows::Graphics::Display::AdvancedColorInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation5)->add_AdvancedColorInfoChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged_revoker consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AdvancedColorInfoChanged_revoker>(this, AdvancedColorInfoChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayInformation5<D>::AdvancedColorInfoChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformation5)->remove_AdvancedColorInfoChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayInformation) consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::GetForCurrentView() const
    {
        void* current{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformationStatics)->GetForCurrentView(&current));
        return winrt::Windows::Graphics::Display::DisplayInformation{ current, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::AutoRotationPreferences() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformationStatics)->get_AutoRotationPreferences(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::AutoRotationPreferences(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformationStatics)->put_AutoRotationPreferences(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformationStatics)->add_DisplayContentsInvalidated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated_revoker consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DisplayContentsInvalidated_revoker>(this, DisplayContentsInvalidated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayInformationStatics<D>::DisplayContentsInvalidated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayInformationStatics)->remove_DisplayContentsInvalidated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::CurrentOrientation() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->get_CurrentOrientation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::NativeOrientation() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->get_NativeOrientation(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::DisplayOrientations) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::AutoRotationPreferences() const
    {
        winrt::Windows::Graphics::Display::DisplayOrientations value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->get_AutoRotationPreferences(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::AutoRotationPreferences(winrt::Windows::Graphics::Display::DisplayOrientations const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->put_AutoRotationPreferences(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->add_OrientationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, OrientationChanged_revoker>(this, OrientationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::OrientationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_OrientationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Display::ResolutionScale) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ResolutionScale() const
    {
        winrt::Windows::Graphics::Display::ResolutionScale value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->get_ResolutionScale(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpi() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->get_LogicalDpi(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->add_LogicalDpiChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, LogicalDpiChanged_revoker>(this, LogicalDpiChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::LogicalDpiChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_LogicalDpiChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->get_StereoEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->add_StereoEnabledChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, StereoEnabledChanged_revoker>(this, StereoEnabledChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::StereoEnabledChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_StereoEnabledChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::GetColorProfileAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->GetColorProfileAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->add_ColorProfileChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ColorProfileChanged_revoker>(this, ColorProfileChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::ColorProfileChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_ColorProfileChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->add_DisplayContentsInvalidated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated_revoker consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DisplayContentsInvalidated_revoker>(this, DisplayContentsInvalidated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Display_IDisplayPropertiesStatics<D>::DisplayContentsInvalidated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayPropertiesStatics)->remove_DisplayContentsInvalidated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::Graphics::DisplayId>) consume_Windows_Graphics_Display_IDisplayServicesStatics<D>::FindAll() const
    {
        uint32_t result_impl_size{};
        struct struct_Windows_Graphics_DisplayId* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Display::IDisplayServicesStatics)->FindAll(&result_impl_size, &result));
        return com_array<winrt::Windows::Graphics::DisplayId>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler, H> final : implements_delegate<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IAdvancedColorInfo> : produce_base<D, winrt::Windows::Graphics::Display::IAdvancedColorInfo>
    {
        int32_t __stdcall get_CurrentAdvancedColorKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::AdvancedColorKind>(this->shim().CurrentAdvancedColorKind());
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
        int32_t __stdcall get_SdrWhiteLevelInNits(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().SdrWhiteLevelInNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsHdrMetadataFormatCurrentlySupported(int32_t format, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsHdrMetadataFormatCurrentlySupported(*reinterpret_cast<winrt::Windows::Graphics::Display::HdrMetadataFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsAdvancedColorKindAvailable(int32_t kind, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsAdvancedColorKindAvailable(*reinterpret_cast<winrt::Windows::Graphics::Display::AdvancedColorKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IBrightnessOverride> : produce_base<D, winrt::Windows::Graphics::Display::IBrightnessOverride>
    {
        int32_t __stdcall get_IsSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOverrideActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOverrideActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BrightnessLevel(double* level) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *level = detach_from<double>(this->shim().BrightnessLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBrightnessLevel(double brightnessLevel, uint32_t options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBrightnessLevel(brightnessLevel, *reinterpret_cast<winrt::Windows::Graphics::Display::DisplayBrightnessOverrideOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBrightnessScenario(int32_t scenario, uint32_t options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBrightnessScenario(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayBrightnessScenario const*>(&scenario), *reinterpret_cast<winrt::Windows::Graphics::Display::DisplayBrightnessOverrideOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLevelForScenario(int32_t scenario, double* brightnessLevel) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *brightnessLevel = detach_from<double>(this->shim().GetLevelForScenario(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayBrightnessScenario const*>(&scenario)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartOverride() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopOverride() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_IsSupportedChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsSupportedChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsSupportedChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsSupportedChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_IsOverrideActiveChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsOverrideActiveChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsOverrideActiveChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOverrideActiveChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_BrightnessLevelChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BrightnessLevelChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::BrightnessOverride, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BrightnessLevelChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BrightnessLevelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IBrightnessOverrideSettings> : produce_base<D, winrt::Windows::Graphics::Display::IBrightnessOverrideSettings>
    {
        int32_t __stdcall get_DesiredLevel(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DesiredLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredNits(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().DesiredNits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics> : produce_base<D, winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics>
    {
        int32_t __stdcall CreateFromLevel(double level, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().CreateFromLevel(level));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromNits(float nits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().CreateFromNits(nits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromDisplayBrightnessOverrideScenario(int32_t overrideScenario, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().CreateFromDisplayBrightnessOverrideScenario(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayBrightnessOverrideScenario const*>(&overrideScenario)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IBrightnessOverrideStatics> : produce_base<D, winrt::Windows::Graphics::Display::IBrightnessOverrideStatics>
    {
        int32_t __stdcall GetDefaultForSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::BrightnessOverride>(this->shim().GetDefaultForSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetForCurrentView(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::BrightnessOverride>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveForSystemAsync(void* value, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().SaveForSystemAsync(*reinterpret_cast<winrt::Windows::Graphics::Display::BrightnessOverride const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IColorOverrideSettings> : produce_base<D, winrt::Windows::Graphics::Display::IColorOverrideSettings>
    {
        int32_t __stdcall get_DesiredDisplayColorOverrideScenario(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayColorOverrideScenario>(this->shim().DesiredDisplayColorOverrideScenario());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IColorOverrideSettingsStatics> : produce_base<D, winrt::Windows::Graphics::Display::IColorOverrideSettingsStatics>
    {
        int32_t __stdcall CreateFromDisplayColorOverrideScenario(int32_t overrideScenario, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Display::ColorOverrideSettings>(this->shim().CreateFromDisplayColorOverrideScenario(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayColorOverrideScenario const*>(&overrideScenario)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverride> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverride>
    {
        int32_t __stdcall get_ColorOverrideSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::ColorOverrideSettings>(this->shim().ColorOverrideSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ColorOverrideSettings(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ColorOverrideSettings(*reinterpret_cast<winrt::Windows::Graphics::Display::ColorOverrideSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BrightnessOverrideSettings(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::BrightnessOverrideSettings>(this->shim().BrightnessOverrideSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BrightnessOverrideSettings(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BrightnessOverrideSettings(*reinterpret_cast<winrt::Windows::Graphics::Display::BrightnessOverrideSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanOverride(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOverrideActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOverrideActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentDisplayEnhancementOverrideCapabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities>(this->shim().GetCurrentDisplayEnhancementOverrideCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestOverride() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopOverride() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopOverride();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CanOverrideChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CanOverrideChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CanOverrideChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanOverrideChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_IsOverrideActiveChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().IsOverrideActiveChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_IsOverrideActiveChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOverrideActiveChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DisplayEnhancementOverrideCapabilitiesChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DisplayEnhancementOverrideCapabilitiesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayEnhancementOverride, winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DisplayEnhancementOverrideCapabilitiesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayEnhancementOverrideCapabilitiesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities>
    {
        int32_t __stdcall get_IsBrightnessControlSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBrightnessControlSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBrightnessNitsControlSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBrightnessNitsControlSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSupportedNitRanges(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Display::NitRange>>(this->shim().GetSupportedNitRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs>
    {
        int32_t __stdcall get_Capabilities(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideStatics> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideStatics>
    {
        int32_t __stdcall GetForCurrentView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Display::DisplayEnhancementOverride>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayInformation> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayInformation>
    {
        int32_t __stdcall get_CurrentOrientation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().CurrentOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NativeOrientation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().NativeOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_OrientationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OrientationChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OrientationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OrientationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_ResolutionScale(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::ResolutionScale>(this->shim().ResolutionScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LogicalDpi(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().LogicalDpi());
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
        int32_t __stdcall add_DpiChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DpiChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DpiChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DpiChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_StereoEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().StereoEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StereoEnabledChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StereoEnabledChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StereoEnabledChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StereoEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetColorProfileAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetColorProfileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ColorProfileChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ColorProfileChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ColorProfileChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ColorProfileChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayInformation2> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayInformation2>
    {
        int32_t __stdcall get_RawPixelsPerViewPixel(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RawPixelsPerViewPixel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayInformation3> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayInformation3>
    {
        int32_t __stdcall get_DiagonalSizeInInches(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().DiagonalSizeInInches());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayInformation4> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayInformation4>
    {
        int32_t __stdcall get_ScreenWidthInRawPixels(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ScreenWidthInRawPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScreenHeightInRawPixels(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ScreenHeightInRawPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayInformation5> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayInformation5>
    {
        int32_t __stdcall GetAdvancedColorInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::AdvancedColorInfo>(this->shim().GetAdvancedColorInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AdvancedColorInfoChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AdvancedColorInfoChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AdvancedColorInfoChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AdvancedColorInfoChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayInformationStatics> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayInformationStatics>
    {
        int32_t __stdcall GetForCurrentView(void** current) noexcept final try
        {
            clear_abi(current);
            typename D::abi_guard guard(this->shim());
            *current = detach_from<winrt::Windows::Graphics::Display::DisplayInformation>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoRotationPreferences(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().AutoRotationPreferences());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoRotationPreferences(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoRotationPreferences(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DisplayContentsInvalidated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DisplayContentsInvalidated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DisplayContentsInvalidated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayContentsInvalidated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayPropertiesStatics> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayPropertiesStatics>
    {
        int32_t __stdcall get_CurrentOrientation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().CurrentOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NativeOrientation(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().NativeOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoRotationPreferences(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::DisplayOrientations>(this->shim().AutoRotationPreferences());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoRotationPreferences(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoRotationPreferences(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_OrientationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OrientationChanged(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OrientationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OrientationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_ResolutionScale(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Display::ResolutionScale>(this->shim().ResolutionScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LogicalDpi(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().LogicalDpi());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_LogicalDpiChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().LogicalDpiChanged(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LogicalDpiChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LogicalDpiChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_StereoEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().StereoEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StereoEnabledChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StereoEnabledChanged(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StereoEnabledChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StereoEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetColorProfileAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetColorProfileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ColorProfileChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ColorProfileChanged(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ColorProfileChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ColorProfileChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DisplayContentsInvalidated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DisplayContentsInvalidated(*reinterpret_cast<winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DisplayContentsInvalidated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayContentsInvalidated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayServices> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayServices>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Display::IDisplayServicesStatics> : produce_base<D, winrt::Windows::Graphics::Display::IDisplayServicesStatics>
    {
        int32_t __stdcall FindAll(uint32_t* __resultSize, struct struct_Windows_Graphics_DisplayId** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().FindAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Display
{
    constexpr auto operator|(DisplayBrightnessOverrideOptions const left, DisplayBrightnessOverrideOptions const right) noexcept
    {
        return static_cast<DisplayBrightnessOverrideOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayBrightnessOverrideOptions& left, DisplayBrightnessOverrideOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayBrightnessOverrideOptions const left, DisplayBrightnessOverrideOptions const right) noexcept
    {
        return static_cast<DisplayBrightnessOverrideOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayBrightnessOverrideOptions& left, DisplayBrightnessOverrideOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayBrightnessOverrideOptions const value) noexcept
    {
        return static_cast<DisplayBrightnessOverrideOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayBrightnessOverrideOptions const left, DisplayBrightnessOverrideOptions const right) noexcept
    {
        return static_cast<DisplayBrightnessOverrideOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayBrightnessOverrideOptions& left, DisplayBrightnessOverrideOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(DisplayOrientations const left, DisplayOrientations const right) noexcept
    {
        return static_cast<DisplayOrientations>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(DisplayOrientations& left, DisplayOrientations const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(DisplayOrientations const left, DisplayOrientations const right) noexcept
    {
        return static_cast<DisplayOrientations>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(DisplayOrientations& left, DisplayOrientations const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(DisplayOrientations const value) noexcept
    {
        return static_cast<DisplayOrientations>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(DisplayOrientations const left, DisplayOrientations const right) noexcept
    {
        return static_cast<DisplayOrientations>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(DisplayOrientations& left, DisplayOrientations const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto BrightnessOverride::GetDefaultForSystem()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::BrightnessOverride(*)(IBrightnessOverrideStatics const&), BrightnessOverride, IBrightnessOverrideStatics>([](IBrightnessOverrideStatics const& f) { return f.GetDefaultForSystem(); });
    }
    inline auto BrightnessOverride::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::BrightnessOverride(*)(IBrightnessOverrideStatics const&), BrightnessOverride, IBrightnessOverrideStatics>([](IBrightnessOverrideStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto BrightnessOverride::SaveForSystemAsync(winrt::Windows::Graphics::Display::BrightnessOverride const& value)
    {
        return impl::call_factory<BrightnessOverride, IBrightnessOverrideStatics>([&](IBrightnessOverrideStatics const& f) { return f.SaveForSystemAsync(value); });
    }
    inline auto BrightnessOverrideSettings::CreateFromLevel(double level)
    {
        return impl::call_factory<BrightnessOverrideSettings, IBrightnessOverrideSettingsStatics>([&](IBrightnessOverrideSettingsStatics const& f) { return f.CreateFromLevel(level); });
    }
    inline auto BrightnessOverrideSettings::CreateFromNits(float nits)
    {
        return impl::call_factory<BrightnessOverrideSettings, IBrightnessOverrideSettingsStatics>([&](IBrightnessOverrideSettingsStatics const& f) { return f.CreateFromNits(nits); });
    }
    inline auto BrightnessOverrideSettings::CreateFromDisplayBrightnessOverrideScenario(winrt::Windows::Graphics::Display::DisplayBrightnessOverrideScenario const& overrideScenario)
    {
        return impl::call_factory<BrightnessOverrideSettings, IBrightnessOverrideSettingsStatics>([&](IBrightnessOverrideSettingsStatics const& f) { return f.CreateFromDisplayBrightnessOverrideScenario(overrideScenario); });
    }
    inline auto ColorOverrideSettings::CreateFromDisplayColorOverrideScenario(winrt::Windows::Graphics::Display::DisplayColorOverrideScenario const& overrideScenario)
    {
        return impl::call_factory<ColorOverrideSettings, IColorOverrideSettingsStatics>([&](IColorOverrideSettingsStatics const& f) { return f.CreateFromDisplayColorOverrideScenario(overrideScenario); });
    }
    inline auto DisplayEnhancementOverride::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::DisplayEnhancementOverride(*)(IDisplayEnhancementOverrideStatics const&), DisplayEnhancementOverride, IDisplayEnhancementOverrideStatics>([](IDisplayEnhancementOverrideStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto DisplayInformation::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::DisplayInformation(*)(IDisplayInformationStatics const&), DisplayInformation, IDisplayInformationStatics>([](IDisplayInformationStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto DisplayInformation::AutoRotationPreferences()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::DisplayOrientations(*)(IDisplayInformationStatics const&), DisplayInformation, IDisplayInformationStatics>([](IDisplayInformationStatics const& f) { return f.AutoRotationPreferences(); });
    }
    inline auto DisplayInformation::AutoRotationPreferences(winrt::Windows::Graphics::Display::DisplayOrientations const& value)
    {
        impl::call_factory<DisplayInformation, IDisplayInformationStatics>([&](IDisplayInformationStatics const& f) { return f.AutoRotationPreferences(value); });
    }
    inline auto DisplayInformation::DisplayContentsInvalidated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<DisplayInformation, IDisplayInformationStatics>([&](IDisplayInformationStatics const& f) { return f.DisplayContentsInvalidated(handler); });
    }
    inline DisplayInformation::DisplayContentsInvalidated_revoker DisplayInformation::DisplayContentsInvalidated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Display::DisplayInformation, winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<DisplayInformation, winrt::Windows::Graphics::Display::IDisplayInformationStatics>();
        return { f, f.DisplayContentsInvalidated(handler) };
    }
    inline auto DisplayInformation::DisplayContentsInvalidated(winrt::event_token const& token)
    {
        impl::call_factory<DisplayInformation, IDisplayInformationStatics>([&](IDisplayInformationStatics const& f) { return f.DisplayContentsInvalidated(token); });
    }
    inline auto DisplayProperties::CurrentOrientation()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::DisplayOrientations(*)(IDisplayPropertiesStatics const&), DisplayProperties, IDisplayPropertiesStatics>([](IDisplayPropertiesStatics const& f) { return f.CurrentOrientation(); });
    }
    inline auto DisplayProperties::NativeOrientation()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::DisplayOrientations(*)(IDisplayPropertiesStatics const&), DisplayProperties, IDisplayPropertiesStatics>([](IDisplayPropertiesStatics const& f) { return f.NativeOrientation(); });
    }
    inline auto DisplayProperties::AutoRotationPreferences()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::DisplayOrientations(*)(IDisplayPropertiesStatics const&), DisplayProperties, IDisplayPropertiesStatics>([](IDisplayPropertiesStatics const& f) { return f.AutoRotationPreferences(); });
    }
    inline auto DisplayProperties::AutoRotationPreferences(winrt::Windows::Graphics::Display::DisplayOrientations const& value)
    {
        impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.AutoRotationPreferences(value); });
    }
    inline auto DisplayProperties::OrientationChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        return impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.OrientationChanged(handler); });
    }
    inline DisplayProperties::OrientationChanged_revoker DisplayProperties::OrientationChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        auto f = get_activation_factory<DisplayProperties, winrt::Windows::Graphics::Display::IDisplayPropertiesStatics>();
        return { f, f.OrientationChanged(handler) };
    }
    inline auto DisplayProperties::OrientationChanged(winrt::event_token const& token)
    {
        impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.OrientationChanged(token); });
    }
    inline auto DisplayProperties::ResolutionScale()
    {
        return impl::call_factory_cast<winrt::Windows::Graphics::Display::ResolutionScale(*)(IDisplayPropertiesStatics const&), DisplayProperties, IDisplayPropertiesStatics>([](IDisplayPropertiesStatics const& f) { return f.ResolutionScale(); });
    }
    inline auto DisplayProperties::LogicalDpi()
    {
        return impl::call_factory_cast<float(*)(IDisplayPropertiesStatics const&), DisplayProperties, IDisplayPropertiesStatics>([](IDisplayPropertiesStatics const& f) { return f.LogicalDpi(); });
    }
    inline auto DisplayProperties::LogicalDpiChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        return impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.LogicalDpiChanged(handler); });
    }
    inline DisplayProperties::LogicalDpiChanged_revoker DisplayProperties::LogicalDpiChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        auto f = get_activation_factory<DisplayProperties, winrt::Windows::Graphics::Display::IDisplayPropertiesStatics>();
        return { f, f.LogicalDpiChanged(handler) };
    }
    inline auto DisplayProperties::LogicalDpiChanged(winrt::event_token const& token)
    {
        impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.LogicalDpiChanged(token); });
    }
    inline auto DisplayProperties::StereoEnabled()
    {
        return impl::call_factory_cast<bool(*)(IDisplayPropertiesStatics const&), DisplayProperties, IDisplayPropertiesStatics>([](IDisplayPropertiesStatics const& f) { return f.StereoEnabled(); });
    }
    inline auto DisplayProperties::StereoEnabledChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        return impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.StereoEnabledChanged(handler); });
    }
    inline DisplayProperties::StereoEnabledChanged_revoker DisplayProperties::StereoEnabledChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        auto f = get_activation_factory<DisplayProperties, winrt::Windows::Graphics::Display::IDisplayPropertiesStatics>();
        return { f, f.StereoEnabledChanged(handler) };
    }
    inline auto DisplayProperties::StereoEnabledChanged(winrt::event_token const& token)
    {
        impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.StereoEnabledChanged(token); });
    }
    inline auto DisplayProperties::GetColorProfileAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>(*)(IDisplayPropertiesStatics const&), DisplayProperties, IDisplayPropertiesStatics>([](IDisplayPropertiesStatics const& f) { return f.GetColorProfileAsync(); });
    }
    inline auto DisplayProperties::ColorProfileChanged(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        return impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.ColorProfileChanged(handler); });
    }
    inline DisplayProperties::ColorProfileChanged_revoker DisplayProperties::ColorProfileChanged(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        auto f = get_activation_factory<DisplayProperties, winrt::Windows::Graphics::Display::IDisplayPropertiesStatics>();
        return { f, f.ColorProfileChanged(handler) };
    }
    inline auto DisplayProperties::ColorProfileChanged(winrt::event_token const& token)
    {
        impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.ColorProfileChanged(token); });
    }
    inline auto DisplayProperties::DisplayContentsInvalidated(winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        return impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.DisplayContentsInvalidated(handler); });
    }
    inline DisplayProperties::DisplayContentsInvalidated_revoker DisplayProperties::DisplayContentsInvalidated(auto_revoke_t, winrt::Windows::Graphics::Display::DisplayPropertiesEventHandler const& handler)
    {
        auto f = get_activation_factory<DisplayProperties, winrt::Windows::Graphics::Display::IDisplayPropertiesStatics>();
        return { f, f.DisplayContentsInvalidated(handler) };
    }
    inline auto DisplayProperties::DisplayContentsInvalidated(winrt::event_token const& token)
    {
        impl::call_factory<DisplayProperties, IDisplayPropertiesStatics>([&](IDisplayPropertiesStatics const& f) { return f.DisplayContentsInvalidated(token); });
    }
    inline auto DisplayServices::FindAll()
    {
        return impl::call_factory_cast<com_array<winrt::Windows::Graphics::DisplayId>(*)(IDisplayServicesStatics const&), DisplayServices, IDisplayServicesStatics>([](IDisplayServicesStatics const& f) { return f.FindAll(); });
    }
    template <typename L> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(L handler) :
        DisplayPropertiesEventHandler(impl::make_delegate<DisplayPropertiesEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(F* handler) :
        DisplayPropertiesEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(O* object, M method) :
        DisplayPropertiesEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(com_ptr<O>&& object, M method) :
        DisplayPropertiesEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DisplayPropertiesEventHandler::DisplayPropertiesEventHandler(weak_ref<O>&& object, M method) :
        DisplayPropertiesEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DisplayPropertiesEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender) const
    {
        check_hresult((*(impl::abi_t<DisplayPropertiesEventHandler>**)this)->Invoke(*(void**)(&sender)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Graphics::Display::IAdvancedColorInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverride> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverrideSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverrideSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IBrightnessOverrideStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IColorOverrideSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IColorOverrideSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverride> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideCapabilitiesChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayEnhancementOverrideStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformation5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayInformationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayPropertiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayServices> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::IDisplayServicesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::AdvancedColorInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::BrightnessOverride> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::BrightnessOverrideSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::ColorOverrideSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::DisplayEnhancementOverride> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::DisplayEnhancementOverrideCapabilitiesChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::DisplayInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::DisplayProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Display::DisplayServices> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
