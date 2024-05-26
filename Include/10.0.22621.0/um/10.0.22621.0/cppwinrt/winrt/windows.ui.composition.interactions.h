// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Interactions_H
#define WINRT_Windows_UI_Composition_Interactions_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Composition.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Composition.Interactions.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Condition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue)->get_Condition(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Condition(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue)->put_Condition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue)->get_Value(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Value(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue) consume_Windows_UI_Composition_Interactions_ICompositionConditionalValueStatics<D>::Create(winrt::Windows::UI::Composition::Compositor const& compositor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics)->Create(*(void**)(&compositor), &result));
        return winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::Count() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->get_Count(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::Add(winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->Add(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::Remove(winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->Remove(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::RemoveAll() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->RemoveAll());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode) consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionXSourceMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->get_PositionXSourceMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionXSourceMode(winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->put_PositionXSourceMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode) consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionYSourceMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->get_PositionYSourceMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionYSourceMode(winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->put_PositionYSourceMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode) consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::ScaleSourceMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->get_ScaleSourceMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::ScaleSourceMode(winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->put_ScaleSourceMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::InteractionSources() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_InteractionSources(&value));
        return winrt::Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::IsPositionRoundingSuggested() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_IsPositionRoundingSuggested(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxPosition() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_MaxPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxPosition(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->put_MaxPosition(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxScale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_MaxScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxScale(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->put_MaxScale(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinPosition() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_MinPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinPosition(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->put_MinPosition(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinScale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_MinScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinScale(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->put_MinScale(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::NaturalRestingPosition() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_NaturalRestingPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::NaturalRestingScale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_NaturalRestingScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::Owner() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_Owner(&value));
        return winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::PositionInertiaDecayRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_PositionInertiaDecayRate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::PositionInertiaDecayRate(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->put_PositionInertiaDecayRate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::PositionVelocityInPixelsPerSecond() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_PositionVelocityInPixelsPerSecond(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::Scale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_Scale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ScaleInertiaDecayRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_ScaleInertiaDecayRate(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ScaleInertiaDecayRate(winrt::Windows::Foundation::IReference<float> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->put_ScaleInertiaDecayRate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ScaleVelocityInPercentPerSecond() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->get_ScaleVelocityInPercentPerSecond(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::AdjustPositionXIfGreaterThanThreshold(float adjustment, float positionThreshold) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->AdjustPositionXIfGreaterThanThreshold(adjustment, positionThreshold));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::AdjustPositionYIfGreaterThanThreshold(float adjustment, float positionThreshold) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->AdjustPositionYIfGreaterThanThreshold(adjustment, positionThreshold));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ConfigurePositionXInertiaModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const& modifiers) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->ConfigurePositionXInertiaModifiers(*(void**)(&modifiers)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ConfigurePositionYInertiaModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const& modifiers) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->ConfigurePositionYInertiaModifiers(*(void**)(&modifiers)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ConfigureScaleInertiaModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const& modifiers) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->ConfigureScaleInertiaModifiers(*(void**)(&modifiers)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePosition(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePosition(impl::bind_in(value), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePositionBy(winrt::Windows::Foundation::Numerics::float3 const& amount) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePositionBy(impl::bind_in(amount), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePositionWithAnimation(winrt::Windows::UI::Composition::CompositionAnimation const& animation) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePositionWithAnimation(*(void**)(&animation), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePositionWithAdditionalVelocity(winrt::Windows::Foundation::Numerics::float3 const& velocityInPixelsPerSecond) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePositionWithAdditionalVelocity(impl::bind_in(velocityInPixelsPerSecond), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdateScale(float value, winrt::Windows::Foundation::Numerics::float3 const& centerPoint) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdateScale(value, impl::bind_in(centerPoint), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdateScaleWithAnimation(winrt::Windows::UI::Composition::CompositionAnimation const& animation, winrt::Windows::Foundation::Numerics::float3 const& centerPoint) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdateScaleWithAnimation(*(void**)(&animation), impl::bind_in(centerPoint), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdateScaleWithAdditionalVelocity(float velocityInPercentPerSecond, winrt::Windows::Foundation::Numerics::float3 const& centerPoint) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdateScaleWithAdditionalVelocity(velocityInPercentPerSecond, impl::bind_in(centerPoint), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker2<D>::ConfigureCenterPointXInertiaModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker2)->ConfigureCenterPointXInertiaModifiers(*(void**)(&conditionalValues)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker2<D>::ConfigureCenterPointYInertiaModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker2)->ConfigureCenterPointYInertiaModifiers(*(void**)(&conditionalValues)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTracker3<D>::ConfigureVector2PositionInertiaModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> const& modifiers) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker3)->ConfigureVector2PositionInertiaModifiers(*(void**)(&modifiers)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker4<D>::TryUpdatePosition(winrt::Windows::Foundation::Numerics::float3 const& value, winrt::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const& option) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker4)->TryUpdatePositionWithOption(impl::bind_in(value), static_cast<int32_t>(option), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker4<D>::TryUpdatePositionBy(winrt::Windows::Foundation::Numerics::float3 const& amount, winrt::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const& option) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker4)->TryUpdatePositionByWithOption(impl::bind_in(amount), static_cast<int32_t>(option), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IInteractionTracker4<D>::IsInertiaFromImpulse() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker4)->get_IsInertiaFromImpulse(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTracker5<D>::TryUpdatePosition(winrt::Windows::Foundation::Numerics::float3 const& value, winrt::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const& option, winrt::Windows::UI::Composition::Interactions::InteractionTrackerPositionUpdateOption const& posUpdateOption) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTracker5)->TryUpdatePositionWithOption(impl::bind_in(value), static_cast<int32_t>(option), static_cast<int32_t>(posUpdateOption), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs<D>::RequestId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs)->get_RequestId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs2<D>::IsFromBinding() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2)->get_IsFromBinding(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs<D>::RequestId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs)->get_RequestId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs2<D>::IsFromBinding() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2)->get_IsFromBinding(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Condition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->get_Condition(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Condition(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->put_Condition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Motion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->get_Motion(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Motion(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->put_Motion(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotionStatics<D>::Create(winrt::Windows::UI::Composition::Compositor const& compositor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics)->Create(*(void**)(&compositor), &result));
        return winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::Condition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->get_Condition(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::Condition(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->put_Condition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ScalarNaturalMotionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::NaturalMotion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->get_NaturalMotion(&value));
        return winrt::Windows::UI::Composition::ScalarNaturalMotionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::NaturalMotion(winrt::Windows::UI::Composition::ScalarNaturalMotionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->put_NaturalMotion(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotionStatics<D>::Create(winrt::Windows::UI::Composition::Compositor const& compositor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics)->Create(*(void**)(&compositor), &result));
        return winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::Condition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->get_Condition(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::Condition(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->put_Condition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::RestingValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->get_RestingValue(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::RestingValue(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->put_RestingValue(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValueStatics<D>::Create(winrt::Windows::UI::Composition::Compositor const& compositor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics)->Create(*(void**)(&compositor), &result));
        return winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::ModifiedRestingPosition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_ModifiedRestingPosition(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::ModifiedRestingScale() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_ModifiedRestingScale(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::NaturalRestingPosition() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_NaturalRestingPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::NaturalRestingScale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_NaturalRestingScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::PositionVelocityInPixelsPerSecond() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_PositionVelocityInPixelsPerSecond(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::RequestId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_RequestId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::ScaleVelocityInPercentPerSecond() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_ScaleVelocityInPercentPerSecond(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs2<D>::IsInertiaFromImpulse() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2)->get_IsInertiaFromImpulse(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs3<D>::IsFromBinding() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3)->get_IsFromBinding(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs<D>::RequestId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs)->get_RequestId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs2<D>::IsFromBinding() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2)->get_IsFromBinding(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::CustomAnimationStateEntered(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& sender, winrt::Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->CustomAnimationStateEntered(*(void**)(&sender), *(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::IdleStateEntered(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& sender, winrt::Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->IdleStateEntered(*(void**)(&sender), *(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::InertiaStateEntered(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& sender, winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->InertiaStateEntered(*(void**)(&sender), *(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::InteractingStateEntered(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& sender, winrt::Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->InteractingStateEntered(*(void**)(&sender), *(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::RequestIgnored(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& sender, winrt::Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->RequestIgnored(*(void**)(&sender), *(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::ValuesChanged(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& sender, winrt::Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs const& args) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->ValuesChanged(*(void**)(&sender), *(void**)(&args)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTrackerRequestIgnoredArgs<D>::RequestId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs)->get_RequestId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionTracker) consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics<D>::Create(winrt::Windows::UI::Composition::Compositor const& compositor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics)->Create(*(void**)(&compositor), &result));
        return winrt::Windows::UI::Composition::Interactions::InteractionTracker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionTracker) consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics<D>::CreateWithOwner(winrt::Windows::UI::Composition::Compositor const& compositor, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner const& owner) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics)->CreateWithOwner(*(void**)(&compositor), *(void**)(&owner), &result));
        return winrt::Windows::UI::Composition::Interactions::InteractionTracker{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics2<D>::SetBindingMode(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2, winrt::Windows::UI::Composition::Interactions::InteractionBindingAxisModes const& axisMode) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2)->SetBindingMode(*(void**)(&boundTracker1), *(void**)(&boundTracker2), static_cast<uint32_t>(axisMode)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionBindingAxisModes) consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics2<D>::GetBindingMode(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2) const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionBindingAxisModes result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2)->GetBindingMode(*(void**)(&boundTracker1), *(void**)(&boundTracker2), reinterpret_cast<uint32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs<D>::RequestId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs)->get_RequestId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs<D>::Scale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs)->get_Scale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::ExpressionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::Condition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->get_Condition(&value));
        return winrt::Windows::UI::Composition::ExpressionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::Condition(winrt::Windows::UI::Composition::ExpressionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->put_Condition(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Vector2NaturalMotionAnimation) consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::NaturalMotion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->get_NaturalMotion(&value));
        return winrt::Windows::UI::Composition::Vector2NaturalMotionAnimation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::NaturalMotion(winrt::Windows::UI::Composition::Vector2NaturalMotionAnimation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->put_NaturalMotion(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion) consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotionStatics<D>::Create(winrt::Windows::UI::Composition::Compositor const& compositor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics)->Create(*(void**)(&compositor), &result));
        return winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionXRailsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_IsPositionXRailsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionXRailsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_IsPositionXRailsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionYRailsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_IsPositionYRailsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionYRailsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_IsPositionYRailsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ManipulationRedirectionMode() const
    {
        winrt::Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_ManipulationRedirectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ManipulationRedirectionMode(winrt::Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_ManipulationRedirectionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionChainingMode) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXChainingMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionChainingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionXChainingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXChainingMode(winrt::Windows::UI::Composition::Interactions::InteractionChainingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionXChainingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionSourceMode) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXSourceMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionSourceMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionXSourceMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXSourceMode(winrt::Windows::UI::Composition::Interactions::InteractionSourceMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionXSourceMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionChainingMode) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYChainingMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionChainingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionYChainingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYChainingMode(winrt::Windows::UI::Composition::Interactions::InteractionChainingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionYChainingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionSourceMode) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYSourceMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionSourceMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionYSourceMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYSourceMode(winrt::Windows::UI::Composition::Interactions::InteractionSourceMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionYSourceMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionChainingMode) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleChainingMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionChainingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_ScaleChainingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleChainingMode(winrt::Windows::UI::Composition::Interactions::InteractionChainingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_ScaleChainingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionSourceMode) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleSourceMode() const
    {
        winrt::Windows::UI::Composition::Interactions::InteractionSourceMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_ScaleSourceMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleSourceMode(winrt::Windows::UI::Composition::Interactions::InteractionSourceMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_ScaleSourceMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Visual) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_Source(&value));
        return winrt::Windows::UI::Composition::Visual{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::TryRedirectForManipulation(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource)->TryRedirectForManipulation(*(void**)(&pointerPoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::DeltaPosition() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_DeltaPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::DeltaScale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_DeltaScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::PositionVelocity() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_PositionVelocity(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::Scale() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_Scale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ScaleVelocity() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_ScaleVelocity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureCenterPointXModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureCenterPointXModifiers(*(void**)(&conditionalValues)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureCenterPointYModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureCenterPointYModifiers(*(void**)(&conditionalValues)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureDeltaPositionXModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureDeltaPositionXModifiers(*(void**)(&conditionalValues)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureDeltaPositionYModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureDeltaPositionYModifiers(*(void**)(&conditionalValues)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureDeltaScaleModifiers(param::iterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureDeltaScaleModifiers(*(void**)(&conditionalValues)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::InteractionSourceConfiguration) consume_Windows_UI_Composition_Interactions_IVisualInteractionSource3<D>::PointerWheelConfig() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource3)->get_PointerWheelConfig(&value));
        return winrt::Windows::UI::Composition::Interactions::InteractionSourceConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::VisualInteractionSource) consume_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics<D>::Create(winrt::Windows::UI::Composition::Visual const& source) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics)->Create(*(void**)(&source), &result));
        return winrt::Windows::UI::Composition::Interactions::VisualInteractionSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Interactions::VisualInteractionSource) consume_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics2<D>::CreateFromIVisualElement(winrt::Windows::UI::Composition::IVisualElement const& source) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2)->CreateFromIVisualElement(*(void**)(&source), &result));
        return winrt::Windows::UI::Composition::Interactions::VisualInteractionSource{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue> : produce_base<D, winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue>
    {
        int32_t __stdcall get_Condition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Condition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Condition(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics> : produce_base<D, winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics>
    {
        int32_t __stdcall Create(void* compositor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource> : produce_base<D, winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource>
    {
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection> : produce_base<D, winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection>
    {
        int32_t __stdcall get_Count(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Count());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Add(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Add(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Remove(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Remove(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveAll() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration>
    {
        int32_t __stdcall get_PositionXSourceMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode>(this->shim().PositionXSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionXSourceMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionXSourceMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionYSourceMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode>(this->shim().PositionYSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionYSourceMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionYSourceMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleSourceMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode>(this->shim().ScaleSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleSourceMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleSourceMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker>
    {
        int32_t __stdcall get_InteractionSources(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection>(this->shim().InteractionSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPositionRoundingSuggested(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPositionRoundingSuggested());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxPosition(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().MaxPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxPosition(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxPosition(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxScale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MaxScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxScale(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinPosition(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().MinPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinPosition(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinPosition(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinScale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().MinScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MinScale(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MinScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalRestingPosition(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().NaturalRestingPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalRestingScale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().NaturalRestingScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Owner(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner>(this->shim().Owner());
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
        int32_t __stdcall get_PositionInertiaDecayRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>>(this->shim().PositionInertiaDecayRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionInertiaDecayRate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionInertiaDecayRate(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionVelocityInPixelsPerSecond(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().PositionVelocityInPixelsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleInertiaDecayRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().ScaleInertiaDecayRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleInertiaDecayRate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleInertiaDecayRate(*reinterpret_cast<winrt::Windows::Foundation::IReference<float> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleVelocityInPercentPerSecond(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().ScaleVelocityInPercentPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AdjustPositionXIfGreaterThanThreshold(float adjustment, float positionThreshold) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AdjustPositionXIfGreaterThanThreshold(adjustment, positionThreshold);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AdjustPositionYIfGreaterThanThreshold(float adjustment, float positionThreshold) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AdjustPositionYIfGreaterThanThreshold(adjustment, positionThreshold);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigurePositionXInertiaModifiers(void* modifiers) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigurePositionXInertiaModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigurePositionYInertiaModifiers(void* modifiers) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigurePositionYInertiaModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureScaleInertiaModifiers(void* modifiers) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureScaleInertiaModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdatePosition(winrt::Windows::Foundation::Numerics::float3 value, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdatePosition(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdatePositionBy(winrt::Windows::Foundation::Numerics::float3 amount, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionBy(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&amount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdatePositionWithAnimation(void* animation, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionWithAnimation(*reinterpret_cast<winrt::Windows::UI::Composition::CompositionAnimation const*>(&animation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdatePositionWithAdditionalVelocity(winrt::Windows::Foundation::Numerics::float3 velocityInPixelsPerSecond, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionWithAdditionalVelocity(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&velocityInPixelsPerSecond)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdateScale(float value, winrt::Windows::Foundation::Numerics::float3 centerPoint, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdateScale(value, *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&centerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdateScaleWithAnimation(void* animation, winrt::Windows::Foundation::Numerics::float3 centerPoint, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdateScaleWithAnimation(*reinterpret_cast<winrt::Windows::UI::Composition::CompositionAnimation const*>(&animation), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&centerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdateScaleWithAdditionalVelocity(float velocityInPercentPerSecond, winrt::Windows::Foundation::Numerics::float3 centerPoint, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdateScaleWithAdditionalVelocity(velocityInPercentPerSecond, *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&centerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker2>
    {
        int32_t __stdcall ConfigureCenterPointXInertiaModifiers(void* conditionalValues) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureCenterPointXInertiaModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureCenterPointYInertiaModifiers(void* conditionalValues) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureCenterPointYInertiaModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker3> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker3>
    {
        int32_t __stdcall ConfigureVector2PositionInertiaModifiers(void* modifiers) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureVector2PositionInertiaModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker4> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker4>
    {
        int32_t __stdcall TryUpdatePositionWithOption(winrt::Windows::Foundation::Numerics::float3 value, int32_t option, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdatePosition(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryUpdatePositionByWithOption(winrt::Windows::Foundation::Numerics::float3 amount, int32_t option, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionBy(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&amount), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInertiaFromImpulse(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInertiaFromImpulse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker5> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTracker5>
    {
        int32_t __stdcall TryUpdatePositionWithOption(winrt::Windows::Foundation::Numerics::float3 value, int32_t option, int32_t posUpdateOption, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().TryUpdatePosition(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const*>(&option), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerPositionUpdateOption const*>(&posUpdateOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs>
    {
        int32_t __stdcall get_RequestId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2>
    {
        int32_t __stdcall get_IsFromBinding(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs>
    {
        int32_t __stdcall get_RequestId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2>
    {
        int32_t __stdcall get_IsFromBinding(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion>
    {
        int32_t __stdcall get_Condition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Condition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Condition(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Motion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().Motion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Motion(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Motion(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics>
    {
        int32_t __stdcall Create(void* compositor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion>
    {
        int32_t __stdcall get_Condition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Condition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Condition(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalMotion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ScalarNaturalMotionAnimation>(this->shim().NaturalMotion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NaturalMotion(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NaturalMotion(*reinterpret_cast<winrt::Windows::UI::Composition::ScalarNaturalMotionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics>
    {
        int32_t __stdcall Create(void* compositor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue>
    {
        int32_t __stdcall get_Condition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Condition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Condition(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RestingValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().RestingValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RestingValue(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RestingValue(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics>
    {
        int32_t __stdcall Create(void* compositor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs>
    {
        int32_t __stdcall get_ModifiedRestingPosition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::Numerics::float3>>(this->shim().ModifiedRestingPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ModifiedRestingScale(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().ModifiedRestingScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalRestingPosition(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().NaturalRestingPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalRestingScale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().NaturalRestingScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionVelocityInPixelsPerSecond(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().PositionVelocityInPixelsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleVelocityInPercentPerSecond(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().ScaleVelocityInPercentPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2>
    {
        int32_t __stdcall get_IsInertiaFromImpulse(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInertiaFromImpulse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3>
    {
        int32_t __stdcall get_IsFromBinding(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs>
    {
        int32_t __stdcall get_RequestId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2>
    {
        int32_t __stdcall get_IsFromBinding(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner>
    {
        int32_t __stdcall CustomAnimationStateEntered(void* sender, void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomAnimationStateEntered(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IdleStateEntered(void* sender, void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IdleStateEntered(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InertiaStateEntered(void* sender, void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InertiaStateEntered(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InteractingStateEntered(void* sender, void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InteractingStateEntered(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestIgnored(void* sender, void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestIgnored(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ValuesChanged(void* sender, void* args) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ValuesChanged(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs>
    {
        int32_t __stdcall get_RequestId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics>
    {
        int32_t __stdcall Create(void* compositor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionTracker>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithOwner(void* compositor, void* owner, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionTracker>(this->shim().CreateWithOwner(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2>
    {
        int32_t __stdcall SetBindingMode(void* boundTracker1, void* boundTracker2, uint32_t axisMode) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBindingMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker1), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker2), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionBindingAxisModes const*>(&axisMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBindingMode(void* boundTracker1, void* boundTracker2, uint32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionBindingAxisModes>(this->shim().GetBindingMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker1), *reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs>
    {
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RequestId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion>
    {
        int32_t __stdcall get_Condition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Condition(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Condition(*reinterpret_cast<winrt::Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalMotion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Vector2NaturalMotionAnimation>(this->shim().NaturalMotion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NaturalMotion(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NaturalMotion(*reinterpret_cast<winrt::Windows::UI::Composition::Vector2NaturalMotionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics>
    {
        int32_t __stdcall Create(void* compositor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource>
    {
        int32_t __stdcall get_IsPositionXRailsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPositionXRailsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPositionXRailsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPositionXRailsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPositionYRailsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPositionYRailsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPositionYRailsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPositionYRailsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManipulationRedirectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode>(this->shim().ManipulationRedirectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ManipulationRedirectionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ManipulationRedirectionMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionXChainingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionChainingMode>(this->shim().PositionXChainingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionXChainingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionXChainingMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionChainingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionXSourceMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionSourceMode>(this->shim().PositionXSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionXSourceMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionXSourceMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionSourceMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionYChainingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionChainingMode>(this->shim().PositionYChainingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionYChainingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionYChainingMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionChainingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionYSourceMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionSourceMode>(this->shim().PositionYSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionYSourceMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionYSourceMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionSourceMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleChainingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionChainingMode>(this->shim().ScaleChainingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleChainingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleChainingMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionChainingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleSourceMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionSourceMode>(this->shim().ScaleSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScaleSourceMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScaleSourceMode(*reinterpret_cast<winrt::Windows::UI::Composition::Interactions::InteractionSourceMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Visual>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRedirectForManipulation(void* pointerPoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TryRedirectForManipulation(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2>
    {
        int32_t __stdcall get_DeltaPosition(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().DeltaPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeltaScale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().DeltaScale());
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
        int32_t __stdcall get_PositionVelocity(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().PositionVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scale(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScaleVelocity(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().ScaleVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureCenterPointXModifiers(void* conditionalValues) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureCenterPointXModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureCenterPointYModifiers(void* conditionalValues) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureCenterPointYModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureDeltaPositionXModifiers(void* conditionalValues) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureDeltaPositionXModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureDeltaPositionYModifiers(void* conditionalValues) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureDeltaPositionYModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConfigureDeltaScaleModifiers(void* conditionalValues) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigureDeltaScaleModifiers(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource3> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource3>
    {
        int32_t __stdcall get_PointerWheelConfig(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Interactions::InteractionSourceConfiguration>(this->shim().PointerWheelConfig());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics>
    {
        int32_t __stdcall Create(void* source, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::VisualInteractionSource>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Composition::Visual const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2> : produce_base<D, winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2>
    {
        int32_t __stdcall CreateFromIVisualElement(void* source, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Composition::Interactions::VisualInteractionSource>(this->shim().CreateFromIVisualElement(*reinterpret_cast<winrt::Windows::UI::Composition::IVisualElement const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Interactions
{
    constexpr auto operator|(InteractionBindingAxisModes const left, InteractionBindingAxisModes const right) noexcept
    {
        return static_cast<InteractionBindingAxisModes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InteractionBindingAxisModes& left, InteractionBindingAxisModes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InteractionBindingAxisModes const left, InteractionBindingAxisModes const right) noexcept
    {
        return static_cast<InteractionBindingAxisModes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InteractionBindingAxisModes& left, InteractionBindingAxisModes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InteractionBindingAxisModes const value) noexcept
    {
        return static_cast<InteractionBindingAxisModes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InteractionBindingAxisModes const left, InteractionBindingAxisModes const right) noexcept
    {
        return static_cast<InteractionBindingAxisModes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InteractionBindingAxisModes& left, InteractionBindingAxisModes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto CompositionConditionalValue::Create(winrt::Windows::UI::Composition::Compositor const& compositor)
    {
        return impl::call_factory<CompositionConditionalValue, ICompositionConditionalValueStatics>([&](ICompositionConditionalValueStatics const& f) { return f.Create(compositor); });
    }
    inline auto InteractionTracker::Create(winrt::Windows::UI::Composition::Compositor const& compositor)
    {
        return impl::call_factory<InteractionTracker, IInteractionTrackerStatics>([&](IInteractionTrackerStatics const& f) { return f.Create(compositor); });
    }
    inline auto InteractionTracker::CreateWithOwner(winrt::Windows::UI::Composition::Compositor const& compositor, winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner const& owner)
    {
        return impl::call_factory<InteractionTracker, IInteractionTrackerStatics>([&](IInteractionTrackerStatics const& f) { return f.CreateWithOwner(compositor, owner); });
    }
    inline auto InteractionTracker::SetBindingMode(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2, winrt::Windows::UI::Composition::Interactions::InteractionBindingAxisModes const& axisMode)
    {
        impl::call_factory<InteractionTracker, IInteractionTrackerStatics2>([&](IInteractionTrackerStatics2 const& f) { return f.SetBindingMode(boundTracker1, boundTracker2, axisMode); });
    }
    inline auto InteractionTracker::GetBindingMode(winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, winrt::Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2)
    {
        return impl::call_factory<InteractionTracker, IInteractionTrackerStatics2>([&](IInteractionTrackerStatics2 const& f) { return f.GetBindingMode(boundTracker1, boundTracker2); });
    }
    inline auto InteractionTrackerInertiaMotion::Create(winrt::Windows::UI::Composition::Compositor const& compositor)
    {
        return impl::call_factory<InteractionTrackerInertiaMotion, IInteractionTrackerInertiaMotionStatics>([&](IInteractionTrackerInertiaMotionStatics const& f) { return f.Create(compositor); });
    }
    inline auto InteractionTrackerInertiaNaturalMotion::Create(winrt::Windows::UI::Composition::Compositor const& compositor)
    {
        return impl::call_factory<InteractionTrackerInertiaNaturalMotion, IInteractionTrackerInertiaNaturalMotionStatics>([&](IInteractionTrackerInertiaNaturalMotionStatics const& f) { return f.Create(compositor); });
    }
    inline auto InteractionTrackerInertiaRestingValue::Create(winrt::Windows::UI::Composition::Compositor const& compositor)
    {
        return impl::call_factory<InteractionTrackerInertiaRestingValue, IInteractionTrackerInertiaRestingValueStatics>([&](IInteractionTrackerInertiaRestingValueStatics const& f) { return f.Create(compositor); });
    }
    inline auto InteractionTrackerVector2InertiaNaturalMotion::Create(winrt::Windows::UI::Composition::Compositor const& compositor)
    {
        return impl::call_factory<InteractionTrackerVector2InertiaNaturalMotion, IInteractionTrackerVector2InertiaNaturalMotionStatics>([&](IInteractionTrackerVector2InertiaNaturalMotionStatics const& f) { return f.Create(compositor); });
    }
    inline auto VisualInteractionSource::Create(winrt::Windows::UI::Composition::Visual const& source)
    {
        return impl::call_factory<VisualInteractionSource, IVisualInteractionSourceStatics>([&](IVisualInteractionSourceStatics const& f) { return f.Create(source); });
    }
    inline auto VisualInteractionSource::CreateFromIVisualElement(winrt::Windows::UI::Composition::IVisualElement const& source)
    {
        return impl::call_factory<VisualInteractionSource, IVisualInteractionSourceStatics2>([&](IVisualInteractionSourceStatics2 const& f) { return f.CreateFromIVisualElement(source); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionSourceConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTracker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Interactions::VisualInteractionSource> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
