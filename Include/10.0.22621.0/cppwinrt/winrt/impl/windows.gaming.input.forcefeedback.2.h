// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Gaming_Input_ForceFeedback_2_H
#define WINRT_Windows_Gaming_Input_ForceFeedback_2_H
#include "winrt/impl/Windows.Gaming.Input.ForceFeedback.1.h"
WINRT_EXPORT namespace winrt::Windows::Gaming::Input::ForceFeedback
{
    struct __declspec(empty_bases) ConditionForceEffect : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect,
        impl::require<ConditionForceEffect, winrt::Windows::Gaming::Input::ForceFeedback::IConditionForceEffect>
    {
        ConditionForceEffect(std::nullptr_t) noexcept {}
        ConditionForceEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect(ptr, take_ownership_from_abi) {}
        explicit ConditionForceEffect(winrt::Windows::Gaming::Input::ForceFeedback::ConditionForceEffectKind const& effectKind);
    };
    struct __declspec(empty_bases) ConstantForceEffect : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect,
        impl::require<ConstantForceEffect, winrt::Windows::Gaming::Input::ForceFeedback::IConstantForceEffect>
    {
        ConstantForceEffect(std::nullptr_t) noexcept {}
        ConstantForceEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect(ptr, take_ownership_from_abi) {}
        ConstantForceEffect();
    };
    struct __declspec(empty_bases) ForceFeedbackMotor : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor
    {
        ForceFeedbackMotor(std::nullptr_t) noexcept {}
        ForceFeedbackMotor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackMotor(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PeriodicForceEffect : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect,
        impl::require<PeriodicForceEffect, winrt::Windows::Gaming::Input::ForceFeedback::IPeriodicForceEffect>
    {
        PeriodicForceEffect(std::nullptr_t) noexcept {}
        PeriodicForceEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect(ptr, take_ownership_from_abi) {}
        explicit PeriodicForceEffect(winrt::Windows::Gaming::Input::ForceFeedback::PeriodicForceEffectKind const& effectKind);
    };
    struct __declspec(empty_bases) RampForceEffect : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect,
        impl::require<RampForceEffect, winrt::Windows::Gaming::Input::ForceFeedback::IRampForceEffect>
    {
        RampForceEffect(std::nullptr_t) noexcept {}
        RampForceEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Gaming::Input::ForceFeedback::IForceFeedbackEffect(ptr, take_ownership_from_abi) {}
        RampForceEffect();
    };
}
#endif
