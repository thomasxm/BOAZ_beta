// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Preview_Injection_H
#define WINRT_Windows_UI_Input_Preview_Injection_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Input.Preview.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Gaming.Input.2.h"
#include "winrt/impl/Windows.UI.Input.Preview.Injection.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Gaming::Input::GamepadButtons) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::Buttons() const
    {
        winrt::Windows::Gaming::Input::GamepadButtons value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_Buttons(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::Buttons(winrt::Windows::Gaming::Input::GamepadButtons const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_Buttons(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_LeftThumbstickX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_LeftThumbstickX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_LeftThumbstickY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftThumbstickY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_LeftThumbstickY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftTrigger() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_LeftTrigger(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::LeftTrigger(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_LeftTrigger(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickX() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_RightThumbstickX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickX(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_RightThumbstickX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickY() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_RightThumbstickY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightThumbstickY(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_RightThumbstickY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightTrigger() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->get_RightTrigger(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfo<D>::RightTrigger(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo)->put_RightTrigger(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo) consume_Windows_UI_Input_Preview_Injection_IInjectedInputGamepadInfoFactory<D>::CreateInstance(winrt::Windows::Gaming::Input::GamepadReading const& reading) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory)->CreateInstanceFromGamepadReading(impl::bind_in(reading), &value));
        return winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions) consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::KeyOptions() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->get_KeyOptions(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::KeyOptions(winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->put_KeyOptions(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::ScanCode() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->get_ScanCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::ScanCode(uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->put_ScanCode(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::VirtualKey() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->get_VirtualKey(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputKeyboardInfo<D>::VirtualKey(uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo)->put_VirtualKey(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseOptions() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_MouseOptions(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseOptions(winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_MouseOptions(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseData() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_MouseData(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::MouseData(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_MouseData(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaY() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_DeltaY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaY(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_DeltaY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaX() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_DeltaX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::DeltaX(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_DeltaX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::TimeOffsetInMilliseconds() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->get_TimeOffsetInMilliseconds(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputMouseInfo<D>::TimeOffsetInMilliseconds(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo)->put_TimeOffsetInMilliseconds(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PointerInfo() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_PointerInfo(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PointerInfo(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_PointerInfo(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenButtons) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenButtons() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenButtons value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_PenButtons(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenButtons(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenButtons const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_PenButtons(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenParameters) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenParameters() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenParameters value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_PenParameters(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::PenParameters(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenParameters const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_PenParameters(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Pressure() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_Pressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Pressure(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_Pressure(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Rotation() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_Rotation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::Rotation(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_Rotation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltX() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_TiltX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltX(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_TiltX(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltY() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->get_TiltY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputPenInfo<D>::TiltY(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo)->put_TiltY(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputRectangle) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Contact() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputRectangle value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_Contact(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Contact(winrt::Windows::UI::Input::Preview::Injection::InjectedInputRectangle const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_Contact(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Orientation() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_Orientation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Orientation(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_Orientation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::PointerInfo() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_PointerInfo(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::PointerInfo(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_PointerInfo(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Pressure() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_Pressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::Pressure(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_Pressure(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::TouchParameters() const
    {
        winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->get_TouchParameters(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInjectedInputTouchInfo<D>::TouchParameters(winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo)->put_TouchParameters(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectKeyboardInput(param::iterable<winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> const& input) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->InjectKeyboardInput(*(void**)(&input)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectMouseInput(param::iterable<winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> const& input) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->InjectMouseInput(*(void**)(&input)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InitializeTouchInjection(winrt::Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const& visualMode) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->InitializeTouchInjection(static_cast<int32_t>(visualMode)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectTouchInput(param::iterable<winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> const& input) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->InjectTouchInput(*(void**)(&input)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::UninitializeTouchInjection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->UninitializeTouchInjection());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InitializePenInjection(winrt::Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const& visualMode) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->InitializePenInjection(static_cast<int32_t>(visualMode)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectPenInput(winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenInfo const& input) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->InjectPenInput(*(void**)(&input)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::UninitializePenInjection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->UninitializePenInjection());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector<D>::InjectShortcut(winrt::Windows::UI::Input::Preview::Injection::InjectedInputShortcut const& shortcut) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector)->InjectShortcut(static_cast<int32_t>(shortcut)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector2<D>::InitializeGamepadInjection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector2)->InitializeGamepadInjection());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector2<D>::InjectGamepadInput(winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo const& input) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector2)->InjectGamepadInput(*(void**)(&input)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Preview_Injection_IInputInjector2<D>::UninitializeGamepadInjection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjector2)->UninitializeGamepadInjection());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InputInjector) consume_Windows_UI_Input_Preview_Injection_IInputInjectorStatics<D>::TryCreate() const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics)->TryCreate(&instance));
        return winrt::Windows::UI::Input::Preview::Injection::InputInjector{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Preview::Injection::InputInjector) consume_Windows_UI_Input_Preview_Injection_IInputInjectorStatics2<D>::TryCreateForAppBroadcastOnly() const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics2)->TryCreateForAppBroadcastOnly(&instance));
        return winrt::Windows::UI::Input::Preview::Injection::InputInjector{ instance, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo>
    {
        int32_t __stdcall get_Buttons(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Gaming::Input::GamepadButtons>(this->shim().Buttons());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Buttons(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Buttons(*reinterpret_cast<winrt::Windows::Gaming::Input::GamepadButtons const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LeftThumbstickX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().LeftThumbstickX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LeftThumbstickX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LeftThumbstickX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LeftThumbstickY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().LeftThumbstickY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LeftThumbstickY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LeftThumbstickY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LeftTrigger(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().LeftTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LeftTrigger(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LeftTrigger(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RightThumbstickX(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RightThumbstickX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RightThumbstickX(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RightThumbstickX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RightThumbstickY(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RightThumbstickY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RightThumbstickY(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RightThumbstickY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RightTrigger(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RightTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RightTrigger(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RightTrigger(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory>
    {
        int32_t __stdcall CreateInstanceFromGamepadReading(struct struct_Windows_Gaming_Input_GamepadReading reading, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Gaming::Input::GamepadReading const*>(&reading)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo>
    {
        int32_t __stdcall get_KeyOptions(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions>(this->shim().KeyOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_KeyOptions(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyOptions(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScanCode(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ScanCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScanCode(uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScanCode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VirtualKey(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_VirtualKey(uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VirtualKey(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo>
    {
        int32_t __stdcall get_MouseOptions(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions>(this->shim().MouseOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MouseOptions(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseOptions(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MouseData(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MouseData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MouseData(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MouseData(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeltaY(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DeltaY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeltaY(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeltaY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeltaX(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DeltaX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DeltaX(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeltaX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimeOffsetInMilliseconds(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().TimeOffsetInMilliseconds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TimeOffsetInMilliseconds(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TimeOffsetInMilliseconds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo>
    {
        int32_t __stdcall get_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo>(this->shim().PointerInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerInfo(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PenButtons(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenButtons>(this->shim().PenButtons());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PenButtons(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PenButtons(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenButtons const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PenParameters(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenParameters>(this->shim().PenParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PenParameters(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PenParameters(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenParameters const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pressure(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Pressure(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pressure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rotation(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Rotation(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rotation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TiltX(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().TiltX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TiltX(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TiltX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TiltY(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().TiltY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TiltY(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TiltY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo>
    {
        int32_t __stdcall get_Contact(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputRectangle* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::Preview::Injection::InjectedInputRectangle>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputRectangle>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Contact(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputRectangle value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Contact(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputRectangle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orientation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Orientation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Orientation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo>(this->shim().PointerInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerInfo(struct struct_Windows_UI_Input_Preview_Injection_InjectedInputPointerInfo value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerInfo(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPointerInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pressure(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Pressure(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Pressure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TouchParameters(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters>(this->shim().TouchParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TouchParameters(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TouchParameters(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchParameters const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjector> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjector>
    {
        int32_t __stdcall InjectKeyboardInput(void* input) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InjectKeyboardInput(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InjectMouseInput(void* input) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InjectMouseInput(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InitializeTouchInjection(int32_t visualMode) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InitializeTouchInjection(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const*>(&visualMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InjectTouchInput(void* input) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InjectTouchInput(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UninitializeTouchInjection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UninitializeTouchInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InitializePenInjection(int32_t visualMode) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InitializePenInjection(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputVisualizationMode const*>(&visualMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InjectPenInput(void* input) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InjectPenInput(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenInfo const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UninitializePenInjection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UninitializePenInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InjectShortcut(int32_t shortcut) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InjectShortcut(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputShortcut const*>(&shortcut));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjector2> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjector2>
    {
        int32_t __stdcall InitializeGamepadInjection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InitializeGamepadInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InjectGamepadInput(void* input) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InjectGamepadInput(*reinterpret_cast<winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo const*>(&input));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UninitializeGamepadInjection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UninitializeGamepadInjection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics>
    {
        int32_t __stdcall TryCreate(void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::UI::Input::Preview::Injection::InputInjector>(this->shim().TryCreate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics2> : produce_base<D, winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics2>
    {
        int32_t __stdcall TryCreateForAppBroadcastOnly(void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::UI::Input::Preview::Injection::InputInjector>(this->shim().TryCreateForAppBroadcastOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview::Injection
{
    constexpr auto operator|(InjectedInputKeyOptions const left, InjectedInputKeyOptions const right) noexcept
    {
        return static_cast<InjectedInputKeyOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InjectedInputKeyOptions& left, InjectedInputKeyOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InjectedInputKeyOptions const left, InjectedInputKeyOptions const right) noexcept
    {
        return static_cast<InjectedInputKeyOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InjectedInputKeyOptions& left, InjectedInputKeyOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InjectedInputKeyOptions const value) noexcept
    {
        return static_cast<InjectedInputKeyOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InjectedInputKeyOptions const left, InjectedInputKeyOptions const right) noexcept
    {
        return static_cast<InjectedInputKeyOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InjectedInputKeyOptions& left, InjectedInputKeyOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(InjectedInputMouseOptions const left, InjectedInputMouseOptions const right) noexcept
    {
        return static_cast<InjectedInputMouseOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InjectedInputMouseOptions& left, InjectedInputMouseOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InjectedInputMouseOptions const left, InjectedInputMouseOptions const right) noexcept
    {
        return static_cast<InjectedInputMouseOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InjectedInputMouseOptions& left, InjectedInputMouseOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InjectedInputMouseOptions const value) noexcept
    {
        return static_cast<InjectedInputMouseOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InjectedInputMouseOptions const left, InjectedInputMouseOptions const right) noexcept
    {
        return static_cast<InjectedInputMouseOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InjectedInputMouseOptions& left, InjectedInputMouseOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(InjectedInputPenButtons const left, InjectedInputPenButtons const right) noexcept
    {
        return static_cast<InjectedInputPenButtons>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InjectedInputPenButtons& left, InjectedInputPenButtons const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InjectedInputPenButtons const left, InjectedInputPenButtons const right) noexcept
    {
        return static_cast<InjectedInputPenButtons>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InjectedInputPenButtons& left, InjectedInputPenButtons const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InjectedInputPenButtons const value) noexcept
    {
        return static_cast<InjectedInputPenButtons>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InjectedInputPenButtons const left, InjectedInputPenButtons const right) noexcept
    {
        return static_cast<InjectedInputPenButtons>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InjectedInputPenButtons& left, InjectedInputPenButtons const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(InjectedInputPenParameters const left, InjectedInputPenParameters const right) noexcept
    {
        return static_cast<InjectedInputPenParameters>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InjectedInputPenParameters& left, InjectedInputPenParameters const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InjectedInputPenParameters const left, InjectedInputPenParameters const right) noexcept
    {
        return static_cast<InjectedInputPenParameters>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InjectedInputPenParameters& left, InjectedInputPenParameters const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InjectedInputPenParameters const value) noexcept
    {
        return static_cast<InjectedInputPenParameters>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InjectedInputPenParameters const left, InjectedInputPenParameters const right) noexcept
    {
        return static_cast<InjectedInputPenParameters>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InjectedInputPenParameters& left, InjectedInputPenParameters const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(InjectedInputPointerOptions const left, InjectedInputPointerOptions const right) noexcept
    {
        return static_cast<InjectedInputPointerOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InjectedInputPointerOptions& left, InjectedInputPointerOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InjectedInputPointerOptions const left, InjectedInputPointerOptions const right) noexcept
    {
        return static_cast<InjectedInputPointerOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InjectedInputPointerOptions& left, InjectedInputPointerOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InjectedInputPointerOptions const value) noexcept
    {
        return static_cast<InjectedInputPointerOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InjectedInputPointerOptions const left, InjectedInputPointerOptions const right) noexcept
    {
        return static_cast<InjectedInputPointerOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InjectedInputPointerOptions& left, InjectedInputPointerOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(InjectedInputTouchParameters const left, InjectedInputTouchParameters const right) noexcept
    {
        return static_cast<InjectedInputTouchParameters>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InjectedInputTouchParameters& left, InjectedInputTouchParameters const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InjectedInputTouchParameters const left, InjectedInputTouchParameters const right) noexcept
    {
        return static_cast<InjectedInputTouchParameters>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InjectedInputTouchParameters& left, InjectedInputTouchParameters const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InjectedInputTouchParameters const value) noexcept
    {
        return static_cast<InjectedInputTouchParameters>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InjectedInputTouchParameters const left, InjectedInputTouchParameters const right) noexcept
    {
        return static_cast<InjectedInputTouchParameters>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InjectedInputTouchParameters& left, InjectedInputTouchParameters const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline InjectedInputGamepadInfo::InjectedInputGamepadInfo() :
        InjectedInputGamepadInfo(impl::call_factory_cast<InjectedInputGamepadInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), InjectedInputGamepadInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InjectedInputGamepadInfo>(); }))
    {
    }
    inline InjectedInputGamepadInfo::InjectedInputGamepadInfo(winrt::Windows::Gaming::Input::GamepadReading const& reading) :
        InjectedInputGamepadInfo(impl::call_factory<InjectedInputGamepadInfo, IInjectedInputGamepadInfoFactory>([&](IInjectedInputGamepadInfoFactory const& f) { return f.CreateInstance(reading); }))
    {
    }
    inline InjectedInputKeyboardInfo::InjectedInputKeyboardInfo() :
        InjectedInputKeyboardInfo(impl::call_factory_cast<InjectedInputKeyboardInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), InjectedInputKeyboardInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InjectedInputKeyboardInfo>(); }))
    {
    }
    inline InjectedInputMouseInfo::InjectedInputMouseInfo() :
        InjectedInputMouseInfo(impl::call_factory_cast<InjectedInputMouseInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), InjectedInputMouseInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InjectedInputMouseInfo>(); }))
    {
    }
    inline InjectedInputPenInfo::InjectedInputPenInfo() :
        InjectedInputPenInfo(impl::call_factory_cast<InjectedInputPenInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), InjectedInputPenInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InjectedInputPenInfo>(); }))
    {
    }
    inline InjectedInputTouchInfo::InjectedInputTouchInfo() :
        InjectedInputTouchInfo(impl::call_factory_cast<InjectedInputTouchInfo(*)(winrt::Windows::Foundation::IActivationFactory const&), InjectedInputTouchInfo>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InjectedInputTouchInfo>(); }))
    {
    }
    inline auto InputInjector::TryCreate()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::Preview::Injection::InputInjector(*)(IInputInjectorStatics const&), InputInjector, IInputInjectorStatics>([](IInputInjectorStatics const& f) { return f.TryCreate(); });
    }
    inline auto InputInjector::TryCreateForAppBroadcastOnly()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::Preview::Injection::InputInjector(*)(IInputInjectorStatics2 const&), InputInjector, IInputInjectorStatics2>([](IInputInjectorStatics2 const& f) { return f.TryCreateForAppBroadcastOnly(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputGamepadInfoFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputKeyboardInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputMouseInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputPenInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInjectedInputTouchInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjector2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::IInputInjectorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputGamepadInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputKeyboardInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputMouseInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputPenInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InjectedInputTouchInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Preview::Injection::InputInjector> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
