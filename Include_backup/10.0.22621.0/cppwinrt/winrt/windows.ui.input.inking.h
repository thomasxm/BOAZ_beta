// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Inking_H
#define WINRT_Windows_UI_Input_Inking_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Input.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Color() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->get_Color(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Color(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->put_Color(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::PenTipShape) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::PenTip() const
    {
        winrt::Windows::UI::Input::Inking::PenTipShape value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->get_PenTip(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::PenTip(winrt::Windows::UI::Input::Inking::PenTipShape const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->put_PenTip(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Size() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->get_Size(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::Size(winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->put_Size(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::IgnorePressure() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->get_IgnorePressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::IgnorePressure(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->put_IgnorePressure(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::FitToCurve() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->get_FitToCurve(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes<D>::FitToCurve(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes)->put_FitToCurve(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3x2) consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::PenTipTransform() const
    {
        winrt::Windows::Foundation::Numerics::float3x2 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2)->get_PenTipTransform(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::PenTipTransform(winrt::Windows::Foundation::Numerics::float3x2 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2)->put_PenTipTransform(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::DrawAsHighlighter() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2)->get_DrawAsHighlighter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes2<D>::DrawAsHighlighter(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2)->put_DrawAsHighlighter(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkDrawingAttributesKind) consume_Windows_UI_Input_Inking_IInkDrawingAttributes3<D>::Kind() const
    {
        winrt::Windows::UI::Input::Inking::InkDrawingAttributesKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties) consume_Windows_UI_Input_Inking_IInkDrawingAttributes3<D>::PencilProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3)->get_PencilProperties(&value));
        return winrt::Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkDrawingAttributes4<D>::IgnoreTilt() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4)->get_IgnoreTilt(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributes4<D>::IgnoreTilt(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4)->put_IgnoreTilt(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkModelerAttributes) consume_Windows_UI_Input_Inking_IInkDrawingAttributes5<D>::ModelerAttributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributes5)->get_ModelerAttributes(&value));
        return winrt::Windows::UI::Input::Inking::InkModelerAttributes{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Inking_IInkDrawingAttributesPencilProperties<D>::Opacity() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties)->get_Opacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkDrawingAttributesPencilProperties<D>::Opacity(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties)->put_Opacity(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkDrawingAttributes) consume_Windows_UI_Input_Inking_IInkDrawingAttributesStatics<D>::CreateForPencil() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkDrawingAttributesStatics)->CreateForPencil(&result));
        return winrt::Windows::UI::Input::Inking::InkDrawingAttributes{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsPrimaryBarrelButtonInputEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputConfiguration)->get_IsPrimaryBarrelButtonInputEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsPrimaryBarrelButtonInputEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputConfiguration)->put_IsPrimaryBarrelButtonInputEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsEraserInputEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputConfiguration)->get_IsEraserInputEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkInputConfiguration<D>::IsEraserInputEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputConfiguration)->put_IsEraserInputEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkInputConfiguration2<D>::IsPenHapticFeedbackEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputConfiguration2)->get_IsPenHapticFeedbackEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkInputConfiguration2<D>::IsPenHapticFeedbackEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputConfiguration2)->put_IsPenHapticFeedbackEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkInputProcessingMode) consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::Mode() const
    {
        winrt::Windows::UI::Input::Inking::InkInputProcessingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::Mode(winrt::Windows::UI::Input::Inking::InkInputProcessingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkInputRightDragAction) consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::RightDragAction() const
    {
        winrt::Windows::UI::Input::Inking::InkInputRightDragAction value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->get_RightDragAction(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkInputProcessingConfiguration<D>::RightDragAction(winrt::Windows::UI::Input::Inking::InkInputRightDragAction const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration)->put_RightDragAction(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkManipulationMode) consume_Windows_UI_Input_Inking_IInkManager<D>::Mode() const
    {
        winrt::Windows::UI::Input::Inking::InkManipulationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkManager)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkManager<D>::Mode(winrt::Windows::UI::Input::Inking::InkManipulationMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkManager)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkManager<D>::ProcessPointerDown(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkManager)->ProcessPointerDown(*(void**)(&pointerPoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Input_Inking_IInkManager<D>::ProcessPointerUpdate(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        void* updateInformation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkManager)->ProcessPointerUpdate(*(void**)(&pointerPoint), &updateInformation));
        return winrt::Windows::Foundation::IInspectable{ updateInformation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkManager<D>::ProcessPointerUp(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        winrt::Windows::Foundation::Rect updateRectangle{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkManager)->ProcessPointerUp(*(void**)(&pointerPoint), put_abi(updateRectangle)));
        return updateRectangle;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkManager<D>::SetDefaultDrawingAttributes(winrt::Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkManager)->SetDefaultDrawingAttributes(*(void**)(&drawingAttributes)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>>) consume_Windows_UI_Input_Inking_IInkManager<D>::RecognizeAsync(winrt::Windows::UI::Input::Inking::InkRecognitionTarget const& recognitionTarget) const
    {
        void* recognitionResults{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkManager)->RecognizeAsync2(static_cast<int32_t>(recognitionTarget), &recognitionResults));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>>{ recognitionResults, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::PredictionTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkModelerAttributes)->get_PredictionTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::PredictionTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkModelerAttributes)->put_PredictionTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::ScalingFactor() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkModelerAttributes)->get_ScalingFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkModelerAttributes<D>::ScalingFactor(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkModelerAttributes)->put_ScalingFactor(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkModelerAttributes2<D>::UseVelocityBasedPressure() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkModelerAttributes2)->get_UseVelocityBasedPressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkModelerAttributes2<D>::UseVelocityBasedPressure(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkModelerAttributes2)->put_UseVelocityBasedPressure(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_Inking_IInkPoint<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPoint)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkPoint<D>::Pressure() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPoint)->get_Pressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkPoint2<D>::TiltX() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPoint2)->get_TiltX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkPoint2<D>::TiltY() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPoint2)->get_TiltY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_UI_Input_Inking_IInkPoint2<D>::Timestamp() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPoint2)->get_Timestamp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPoint) consume_Windows_UI_Input_Inking_IInkPointFactory<D>::CreateInkPoint(winrt::Windows::Foundation::Point const& position, float pressure) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPointFactory)->CreateInkPoint(impl::bind_in(position), pressure, &result));
        return winrt::Windows::UI::Input::Inking::InkPoint{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPoint) consume_Windows_UI_Input_Inking_IInkPointFactory2<D>::CreateInkPointWithTiltAndTimestamp(winrt::Windows::Foundation::Point const& position, float pressure, float tiltX, float tiltY, uint64_t timestamp) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPointFactory2)->CreateInkPointWithTiltAndTimestamp(impl::bind_in(position), pressure, tiltX, tiltY, timestamp, &result));
        return winrt::Windows::UI::Input::Inking::InkPoint{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenter<D>::IsInputEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->get_IsInputEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter<D>::IsInputEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->put_IsInputEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreInputDeviceTypes) consume_Windows_UI_Input_Inking_IInkPresenter<D>::InputDeviceTypes() const
    {
        winrt::Windows::UI::Core::CoreInputDeviceTypes value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->get_InputDeviceTypes(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter<D>::InputDeviceTypes(winrt::Windows::UI::Core::CoreInputDeviceTypes const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->put_InputDeviceTypes(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkUnprocessedInput) consume_Windows_UI_Input_Inking_IInkPresenter<D>::UnprocessedInput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->get_UnprocessedInput(&value));
        return winrt::Windows::UI::Input::Inking::InkUnprocessedInput{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStrokeInput) consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokeInput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->get_StrokeInput(&value));
        return winrt::Windows::UI::Input::Inking::InkStrokeInput{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkInputProcessingConfiguration) consume_Windows_UI_Input_Inking_IInkPresenter<D>::InputProcessingConfiguration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->get_InputProcessingConfiguration(&value));
        return winrt::Windows::UI::Input::Inking::InkInputProcessingConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStrokeContainer) consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokeContainer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->get_StrokeContainer(&value));
        return winrt::Windows::UI::Input::Inking::InkStrokeContainer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokeContainer(winrt::Windows::UI::Input::Inking::InkStrokeContainer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->put_StrokeContainer(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkDrawingAttributes) consume_Windows_UI_Input_Inking_IInkPresenter<D>::CopyDefaultDrawingAttributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->CopyDefaultDrawingAttributes(&value));
        return winrt::Windows::UI::Input::Inking::InkDrawingAttributes{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter<D>::UpdateDefaultDrawingAttributes(winrt::Windows::UI::Input::Inking::InkDrawingAttributes const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->UpdateDefaultDrawingAttributes(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkSynchronizer) consume_Windows_UI_Input_Inking_IInkPresenter<D>::ActivateCustomDrying() const
    {
        void* inkSynchronizer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->ActivateCustomDrying(&inkSynchronizer));
        return winrt::Windows::UI::Input::Inking::InkSynchronizer{ inkSynchronizer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter<D>::SetPredefinedConfiguration(winrt::Windows::UI::Input::Inking::InkPresenterPredefinedConfiguration const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->SetPredefinedConfiguration(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkPresenter, winrt::Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->add_StrokesCollected(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected_revoker consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkPresenter, winrt::Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StrokesCollected_revoker>(this, StrokesCollected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesCollected(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->remove_StrokesCollected(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkPresenter, winrt::Windows::UI::Input::Inking::InkStrokesErasedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->add_StrokesErased(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased_revoker consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkPresenter, winrt::Windows::UI::Input::Inking::InkStrokesErasedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StrokesErased_revoker>(this, StrokesErased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter<D>::StrokesErased(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter)->remove_StrokesErased(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkHighContrastAdjustment) consume_Windows_UI_Input_Inking_IInkPresenter2<D>::HighContrastAdjustment() const
    {
        winrt::Windows::UI::Input::Inking::InkHighContrastAdjustment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter2)->get_HighContrastAdjustment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenter2<D>::HighContrastAdjustment(winrt::Windows::UI::Input::Inking::InkHighContrastAdjustment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter2)->put_HighContrastAdjustment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkInputConfiguration) consume_Windows_UI_Input_Inking_IInkPresenter3<D>::InputConfiguration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenter3)->get_InputConfiguration(&value));
        return winrt::Windows::UI::Input::Inking::InkInputConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreTickMarksVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->get_AreTickMarksVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreTickMarksVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->put_AreTickMarksVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreRaysVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->get_AreRaysVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AreRaysVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->put_AreRaysVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsCenterMarkerVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->get_IsCenterMarkerVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsCenterMarkerVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->put_IsCenterMarkerVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsAngleReadoutVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->get_IsAngleReadoutVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsAngleReadoutVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->put_IsAngleReadoutVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsResizable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->get_IsResizable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::IsResizable(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->put_IsResizable(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::Radius() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->get_Radius(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::Radius(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->put_Radius(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AccentColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->get_AccentColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterProtractor<D>::AccentColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractor)->put_AccentColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenterProtractor) consume_Windows_UI_Input_Inking_IInkPresenterProtractorFactory<D>::Create(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const
    {
        void* inkPresenterProtractor{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterProtractorFactory)->Create(*(void**)(&inkPresenter), &inkPresenterProtractor));
        return winrt::Windows::UI::Input::Inking::InkPresenterProtractor{ inkPresenterProtractor, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Length() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler)->get_Length(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Length(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler)->put_Length(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Width() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterRuler<D>::Width(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler)->put_Width(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::AreTickMarksVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler2)->get_AreTickMarksVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::AreTickMarksVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler2)->put_AreTickMarksVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::IsCompassVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler2)->get_IsCompassVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterRuler2<D>::IsCompassVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRuler2)->put_IsCompassVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenterRuler) consume_Windows_UI_Input_Inking_IInkPresenterRulerFactory<D>::Create(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const
    {
        void* inkPresenterRuler{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterRulerFactory)->Create(*(void**)(&inkPresenter), &inkPresenterRuler));
        return winrt::Windows::UI::Input::Inking::InkPresenterRuler{ inkPresenterRuler, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenterStencilKind) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::Kind() const
    {
        winrt::Windows::UI::Input::Inking::InkPresenterStencilKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::IsVisible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->get_IsVisible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::IsVisible(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->put_IsVisible(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::BackgroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->get_BackgroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::BackgroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->put_BackgroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::ForegroundColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->get_ForegroundColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::ForegroundColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->put_ForegroundColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3x2) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::Transform() const
    {
        winrt::Windows::Foundation::Numerics::float3x2 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->get_Transform(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkPresenterStencil<D>::Transform(winrt::Windows::Foundation::Numerics::float3x2 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkPresenterStencil)->put_Transform(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkRecognitionResult<D>::BoundingRect() const
    {
        winrt::Windows::Foundation::Rect boundingRect{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkRecognitionResult)->get_BoundingRect(put_abi(boundingRect)));
        return boundingRect;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_UI_Input_Inking_IInkRecognitionResult<D>::GetTextCandidates() const
    {
        void* textCandidates{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkRecognitionResult)->GetTextCandidates(&textCandidates));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ textCandidates, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>) consume_Windows_UI_Input_Inking_IInkRecognitionResult<D>::GetStrokes() const
    {
        void* strokes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkRecognitionResult)->GetStrokes(&strokes));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>{ strokes, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_IInkRecognizer<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkRecognizer)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkRecognizerContainer<D>::SetDefaultRecognizer(winrt::Windows::UI::Input::Inking::InkRecognizer const& recognizer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkRecognizerContainer)->SetDefaultRecognizer(*(void**)(&recognizer)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>>) consume_Windows_UI_Input_Inking_IInkRecognizerContainer<D>::RecognizeAsync(winrt::Windows::UI::Input::Inking::InkStrokeContainer const& strokeCollection, winrt::Windows::UI::Input::Inking::InkRecognitionTarget const& recognitionTarget) const
    {
        void* recognitionResults{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkRecognizerContainer)->RecognizeAsync(*(void**)(&strokeCollection), static_cast<int32_t>(recognitionTarget), &recognitionResults));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>>{ recognitionResults, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognizer>) consume_Windows_UI_Input_Inking_IInkRecognizerContainer<D>::GetRecognizers() const
    {
        void* recognizerView{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkRecognizerContainer)->GetRecognizers(&recognizerView));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognizer>{ recognizerView, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkDrawingAttributes) consume_Windows_UI_Input_Inking_IInkStroke<D>::DrawingAttributes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->get_DrawingAttributes(&value));
        return winrt::Windows::UI::Input::Inking::InkDrawingAttributes{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStroke<D>::DrawingAttributes(winrt::Windows::UI::Input::Inking::InkDrawingAttributes const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->put_DrawingAttributes(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkStroke<D>::BoundingRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->get_BoundingRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkStroke<D>::Selected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->get_Selected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStroke<D>::Selected(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->put_Selected(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkStroke<D>::Recognized() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->get_Recognized(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStrokeRenderingSegment>) consume_Windows_UI_Input_Inking_IInkStroke<D>::GetRenderingSegments() const
    {
        void* renderingSegments{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->GetRenderingSegments(&renderingSegments));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStrokeRenderingSegment>{ renderingSegments, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStroke) consume_Windows_UI_Input_Inking_IInkStroke<D>::Clone() const
    {
        void* clonedStroke{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke)->Clone(&clonedStroke));
        return winrt::Windows::UI::Input::Inking::InkStroke{ clonedStroke, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3x2) consume_Windows_UI_Input_Inking_IInkStroke2<D>::PointTransform() const
    {
        winrt::Windows::Foundation::Numerics::float3x2 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke2)->get_PointTransform(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStroke2<D>::PointTransform(winrt::Windows::Foundation::Numerics::float3x2 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke2)->put_PointTransform(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkPoint>) consume_Windows_UI_Input_Inking_IInkStroke2<D>::GetInkPoints() const
    {
        void* inkPoints{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke2)->GetInkPoints(&inkPoints));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkPoint>{ inkPoints, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_Inking_IInkStroke3<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke3)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeStartedTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke3)->get_StrokeStartedTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeStartedTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke3)->put_StrokeStartedTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeDuration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke3)->get_StrokeDuration(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStroke3<D>::StrokeDuration(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke3)->put_StrokeDuration(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Input_Inking_IInkStroke4<D>::PointerId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStroke4)->get_PointerId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::BeginStroke(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeBuilder)->BeginStroke(*(void**)(&pointerPoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPoint) consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::AppendToStroke(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        void* previousPointerPoint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeBuilder)->AppendToStroke(*(void**)(&pointerPoint), &previousPointerPoint));
        return winrt::Windows::UI::Input::PointerPoint{ previousPointerPoint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStroke) consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::EndStroke(winrt::Windows::UI::Input::PointerPoint const& pointerPoint) const
    {
        void* stroke{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeBuilder)->EndStroke(*(void**)(&pointerPoint), &stroke));
        return winrt::Windows::UI::Input::Inking::InkStroke{ stroke, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStroke) consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::CreateStroke(param::iterable<winrt::Windows::Foundation::Point> const& points) const
    {
        void* stroke{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeBuilder)->CreateStroke(*(void**)(&points), &stroke));
        return winrt::Windows::UI::Input::Inking::InkStroke{ stroke, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeBuilder<D>::SetDefaultDrawingAttributes(winrt::Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeBuilder)->SetDefaultDrawingAttributes(*(void**)(&drawingAttributes)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStroke) consume_Windows_UI_Input_Inking_IInkStrokeBuilder2<D>::CreateStrokeFromInkPoints(param::iterable<winrt::Windows::UI::Input::Inking::InkPoint> const& inkPoints, winrt::Windows::Foundation::Numerics::float3x2 const& transform) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2)->CreateStrokeFromInkPoints(*(void**)(&inkPoints), impl::bind_in(transform), &result));
        return winrt::Windows::UI::Input::Inking::InkStroke{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStroke) consume_Windows_UI_Input_Inking_IInkStrokeBuilder3<D>::CreateStrokeFromInkPoints(param::iterable<winrt::Windows::UI::Input::Inking::InkPoint> const& inkPoints, winrt::Windows::Foundation::Numerics::float3x2 const& transform, winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& strokeStartedTime, winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& strokeDuration) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3)->CreateStrokeFromInkPoints(*(void**)(&inkPoints), impl::bind_in(transform), *(void**)(&strokeStartedTime), *(void**)(&strokeDuration), &result));
        return winrt::Windows::UI::Input::Inking::InkStroke{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::BoundingRect() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->get_BoundingRect(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::AddStroke(winrt::Windows::UI::Input::Inking::InkStroke const& stroke) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->AddStroke(*(void**)(&stroke)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::DeleteSelected() const
    {
        winrt::Windows::Foundation::Rect invalidatedRect{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->DeleteSelected(put_abi(invalidatedRect)));
        return invalidatedRect;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::MoveSelected(winrt::Windows::Foundation::Point const& translation) const
    {
        winrt::Windows::Foundation::Rect invalidatedRectangle{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->MoveSelected(impl::bind_in(translation), put_abi(invalidatedRectangle)));
        return invalidatedRectangle;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::SelectWithPolyLine(param::iterable<winrt::Windows::Foundation::Point> const& polyline) const
    {
        winrt::Windows::Foundation::Rect invalidatedRectangle{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->SelectWithPolyLine(*(void**)(&polyline), put_abi(invalidatedRectangle)));
        return invalidatedRectangle;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::SelectWithLine(winrt::Windows::Foundation::Point const& from, winrt::Windows::Foundation::Point const& to) const
    {
        winrt::Windows::Foundation::Rect invalidatedRectangle{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->SelectWithLine(impl::bind_in(from), impl::bind_in(to), put_abi(invalidatedRectangle)));
        return invalidatedRectangle;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::CopySelectedToClipboard() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->CopySelectedToClipboard());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::PasteFromClipboard(winrt::Windows::Foundation::Point const& position) const
    {
        winrt::Windows::Foundation::Rect invalidatedRectangle{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->PasteFromClipboard(impl::bind_in(position), put_abi(invalidatedRectangle)));
        return invalidatedRectangle;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::CanPasteFromClipboard() const
    {
        bool canPaste{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->CanPasteFromClipboard(&canPaste));
        return canPaste;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncActionWithProgress<uint64_t>) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::LoadAsync(winrt::Windows::Storage::Streams::IInputStream const& inputStream) const
    {
        void* loadAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->LoadAsync(*(void**)(&inputStream), &loadAction));
        return winrt::Windows::Foundation::IAsyncActionWithProgress<uint64_t>{ loadAction, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::SaveAsync(winrt::Windows::Storage::Streams::IOutputStream const& outputStream) const
    {
        void* outputStreamOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->SaveAsync(*(void**)(&outputStream), &outputStreamOperation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>{ outputStreamOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::UpdateRecognitionResults(param::vector_view<winrt::Windows::UI::Input::Inking::InkRecognitionResult> const& recognitionResults) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->UpdateRecognitionResults(*(void**)(&recognitionResults)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::GetStrokes() const
    {
        void* strokeView{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->GetStrokes(&strokeView));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>{ strokeView, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>) consume_Windows_UI_Input_Inking_IInkStrokeContainer<D>::GetRecognitionResults() const
    {
        void* recognitionResults{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer)->GetRecognitionResults(&recognitionResults));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>{ recognitionResults, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeContainer2<D>::AddStrokes(param::iterable<winrt::Windows::UI::Input::Inking::InkStroke> const& strokes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer2)->AddStrokes(*(void**)(&strokes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeContainer2<D>::Clear() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer2)->Clear());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>) consume_Windows_UI_Input_Inking_IInkStrokeContainer3<D>::SaveAsync(winrt::Windows::Storage::Streams::IOutputStream const& outputStream, winrt::Windows::UI::Input::Inking::InkPersistenceFormat const& inkPersistenceFormat) const
    {
        void* outputStreamOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer3)->SaveWithFormatAsync(*(void**)(&outputStream), static_cast<int32_t>(inkPersistenceFormat), &outputStreamOperation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>{ outputStreamOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkStroke) consume_Windows_UI_Input_Inking_IInkStrokeContainer3<D>::GetStrokeById(uint32_t id) const
    {
        void* stroke{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeContainer3)->GetStrokeById(id, &stroke));
        return winrt::Windows::UI::Input::Inking::InkStroke{ stroke, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeStarted(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StrokeStarted_revoker>(this, StrokeStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeStarted(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeStarted(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeContinued(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StrokeContinued_revoker>(this, StrokeContinued(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeContinued(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeContinued(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeEnded(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StrokeEnded_revoker>(this, StrokeEnded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeEnded(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeEnded(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->add_StrokeCanceled(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled_revoker consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StrokeCanceled_revoker>(this, StrokeCanceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::StrokeCanceled(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->remove_StrokeCanceled(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenter) consume_Windows_UI_Input_Inking_IInkStrokeInput<D>::InkPresenter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeInput)->get_InkPresenter(&value));
        return winrt::Windows::UI::Input::Inking::InkPresenter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::Position() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::BezierControlPoint1() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_BezierControlPoint1(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::BezierControlPoint2() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_BezierControlPoint2(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::Pressure() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_Pressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::TiltX() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_TiltX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::TiltY() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_TiltY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Input_Inking_IInkStrokeRenderingSegment<D>::Twist() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment)->get_Twist(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>) consume_Windows_UI_Input_Inking_IInkStrokesCollectedEventArgs<D>::Strokes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs)->get_Strokes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>) consume_Windows_UI_Input_Inking_IInkStrokesErasedEventArgs<D>::Strokes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs)->get_Strokes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>) consume_Windows_UI_Input_Inking_IInkSynchronizer<D>::BeginDry() const
    {
        void* inkStrokes{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkSynchronizer)->BeginDry(&inkStrokes));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>{ inkStrokes, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkSynchronizer<D>::EndDry() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkSynchronizer)->EndDry());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerEntered(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerEntered(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerEntered(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerHovered(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerHovered_revoker>(this, PointerHovered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerHovered(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerHovered(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerExited(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerExited(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerExited(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerMoved(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerMoved(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerMoved(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerReleased(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerReleased(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerReleased(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->add_PointerLost(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost_revoker consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerLost_revoker>(this, PointerLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::PointerLost(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->remove_PointerLost(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::InkPresenter) consume_Windows_UI_Input_Inking_IInkUnprocessedInput<D>::InkPresenter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IInkUnprocessedInput)->get_InkPresenter(&value));
        return winrt::Windows::UI::Input::Inking::InkPresenter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::IsHandwritingDirectlyIntoTextFieldEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettings)->get_IsHandwritingDirectlyIntoTextFieldEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::PenHandedness) consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::PenHandedness() const
    {
        winrt::Windows::UI::Input::Inking::PenHandedness value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettings)->get_PenHandedness(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::HandwritingLineHeight) consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::HandwritingLineHeight() const
    {
        winrt::Windows::UI::Input::Inking::HandwritingLineHeight value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettings)->get_HandwritingLineHeight(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::FontFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettings)->get_FontFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::UserConsentsToHandwritingTelemetryCollection() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettings)->get_UserConsentsToHandwritingTelemetryCollection(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Input_Inking_IPenAndInkSettings<D>::IsTouchHandwritingEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettings)->get_IsTouchHandwritingEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Input_Inking_IPenAndInkSettings2<D>::SetPenHandedness(winrt::Windows::UI::Input::Inking::PenHandedness const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettings2)->SetPenHandedness(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Inking::PenAndInkSettings) consume_Windows_UI_Input_Inking_IPenAndInkSettingsStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Inking::IPenAndInkSettingsStatics)->GetDefault(&result));
        return winrt::Windows::UI::Input::Inking::PenAndInkSettings{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes>
    {
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
        int32_t __stdcall get_PenTip(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::PenTipShape>(this->shim().PenTip());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PenTip(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PenTip(*reinterpret_cast<winrt::Windows::UI::Input::Inking::PenTipShape const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Size(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Size(winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Size(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IgnorePressure(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IgnorePressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IgnorePressure(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IgnorePressure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FitToCurve(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().FitToCurve());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FitToCurve(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FitToCurve(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2>
    {
        int32_t __stdcall get_PenTipTransform(winrt::Windows::Foundation::Numerics::float3x2* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3x2>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3x2>(this->shim().PenTipTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PenTipTransform(winrt::Windows::Foundation::Numerics::float3x2 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PenTipTransform(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DrawAsHighlighter(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DrawAsHighlighter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DrawAsHighlighter(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DrawAsHighlighter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkDrawingAttributesKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PencilProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties>(this->shim().PencilProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4>
    {
        int32_t __stdcall get_IgnoreTilt(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IgnoreTilt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IgnoreTilt(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IgnoreTilt(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes5> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributes5>
    {
        int32_t __stdcall get_ModelerAttributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkModelerAttributes>(this->shim().ModelerAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties>
    {
        int32_t __stdcall get_Opacity(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Opacity(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributesStatics> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkDrawingAttributesStatics>
    {
        int32_t __stdcall CreateForPencil(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Inking::InkDrawingAttributes>(this->shim().CreateForPencil());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkInputConfiguration> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkInputConfiguration>
    {
        int32_t __stdcall get_IsPrimaryBarrelButtonInputEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPrimaryBarrelButtonInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPrimaryBarrelButtonInputEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPrimaryBarrelButtonInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsEraserInputEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEraserInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEraserInputEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEraserInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkInputConfiguration2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkInputConfiguration2>
    {
        int32_t __stdcall get_IsPenHapticFeedbackEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPenHapticFeedbackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPenHapticFeedbackEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPenHapticFeedbackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration>
    {
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkInputProcessingMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkInputProcessingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RightDragAction(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkInputRightDragAction>(this->shim().RightDragAction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RightDragAction(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RightDragAction(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkInputRightDragAction const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkManager> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkManager>
    {
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkManipulationMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkManipulationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessPointerDown(void* pointerPoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessPointerDown(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessPointerUpdate(void* pointerPoint, void** updateInformation) noexcept final try
        {
            clear_abi(updateInformation);
            typename D::abi_guard guard(this->shim());
            *updateInformation = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ProcessPointerUpdate(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessPointerUp(void* pointerPoint, winrt::Windows::Foundation::Rect* updateRectangle) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(updateRectangle);
            typename D::abi_guard guard(this->shim());
            *updateRectangle = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ProcessPointerUp(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDefaultDrawingAttributes(void* drawingAttributes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDefaultDrawingAttributes(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkDrawingAttributes const*>(&drawingAttributes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RecognizeAsync2(int32_t recognitionTarget, void** recognitionResults) noexcept final try
        {
            clear_abi(recognitionResults);
            typename D::abi_guard guard(this->shim());
            *recognitionResults = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>>>(this->shim().RecognizeAsync(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkRecognitionTarget const*>(&recognitionTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkModelerAttributes> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkModelerAttributes>
    {
        int32_t __stdcall get_PredictionTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().PredictionTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PredictionTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PredictionTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScalingFactor(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().ScalingFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScalingFactor(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScalingFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkModelerAttributes2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkModelerAttributes2>
    {
        int32_t __stdcall get_UseVelocityBasedPressure(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UseVelocityBasedPressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UseVelocityBasedPressure(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UseVelocityBasedPressure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPoint> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPoint>
    {
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pressure(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPoint2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPoint2>
    {
        int32_t __stdcall get_TiltX(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().TiltX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TiltY(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().TiltY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timestamp(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPointFactory> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPointFactory>
    {
        int32_t __stdcall CreateInkPoint(winrt::Windows::Foundation::Point position, float pressure, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Inking::InkPoint>(this->shim().CreateInkPoint(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&position), pressure));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPointFactory2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPointFactory2>
    {
        int32_t __stdcall CreateInkPointWithTiltAndTimestamp(winrt::Windows::Foundation::Point position, float pressure, float tiltX, float tiltY, uint64_t timestamp, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Inking::InkPoint>(this->shim().CreateInkPointWithTiltAndTimestamp(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&position), pressure, tiltX, tiltY, timestamp));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenter> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenter>
    {
        int32_t __stdcall get_IsInputEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsInputEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputDeviceTypes(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreInputDeviceTypes>(this->shim().InputDeviceTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InputDeviceTypes(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InputDeviceTypes(*reinterpret_cast<winrt::Windows::UI::Core::CoreInputDeviceTypes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnprocessedInput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkUnprocessedInput>(this->shim().UnprocessedInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeInput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkStrokeInput>(this->shim().StrokeInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputProcessingConfiguration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkInputProcessingConfiguration>(this->shim().InputProcessingConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeContainer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkStrokeContainer>(this->shim().StrokeContainer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeContainer(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeContainer(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkStrokeContainer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyDefaultDrawingAttributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkDrawingAttributes>(this->shim().CopyDefaultDrawingAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateDefaultDrawingAttributes(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateDefaultDrawingAttributes(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkDrawingAttributes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ActivateCustomDrying(void** inkSynchronizer) noexcept final try
        {
            clear_abi(inkSynchronizer);
            typename D::abi_guard guard(this->shim());
            *inkSynchronizer = detach_from<winrt::Windows::UI::Input::Inking::InkSynchronizer>(this->shim().ActivateCustomDrying());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPredefinedConfiguration(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPredefinedConfiguration(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkPresenterPredefinedConfiguration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StrokesCollected(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StrokesCollected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkPresenter, winrt::Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StrokesCollected(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokesCollected(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_StrokesErased(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StrokesErased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkPresenter, winrt::Windows::UI::Input::Inking::InkStrokesErasedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StrokesErased(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokesErased(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenter2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenter2>
    {
        int32_t __stdcall get_HighContrastAdjustment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkHighContrastAdjustment>(this->shim().HighContrastAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HighContrastAdjustment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HighContrastAdjustment(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkHighContrastAdjustment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenter3> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenter3>
    {
        int32_t __stdcall get_InputConfiguration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkInputConfiguration>(this->shim().InputConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenterProtractor> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenterProtractor>
    {
        int32_t __stdcall get_AreTickMarksVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreTickMarksVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AreTickMarksVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AreTickMarksVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AreRaysVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreRaysVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AreRaysVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AreRaysVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCenterMarkerVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCenterMarkerVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCenterMarkerVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCenterMarkerVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsAngleReadoutVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAngleReadoutVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsAngleReadoutVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsAngleReadoutVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsResizable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsResizable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsResizable(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsResizable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Radius(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Radius());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Radius(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Radius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AccentColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().AccentColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AccentColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccentColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenterProtractorFactory> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenterProtractorFactory>
    {
        int32_t __stdcall Create(void* inkPresenter, void** inkPresenterProtractor) noexcept final try
        {
            clear_abi(inkPresenterProtractor);
            typename D::abi_guard guard(this->shim());
            *inkPresenterProtractor = detach_from<winrt::Windows::UI::Input::Inking::InkPresenterProtractor>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkPresenter const*>(&inkPresenter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenterRuler> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenterRuler>
    {
        int32_t __stdcall get_Length(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Length(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Width(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Width(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Width(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenterRuler2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenterRuler2>
    {
        int32_t __stdcall get_AreTickMarksVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AreTickMarksVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AreTickMarksVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AreTickMarksVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCompassVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCompassVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsCompassVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsCompassVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenterRulerFactory> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenterRulerFactory>
    {
        int32_t __stdcall Create(void* inkPresenter, void** inkPresenterRuler) noexcept final try
        {
            clear_abi(inkPresenterRuler);
            typename D::abi_guard guard(this->shim());
            *inkPresenterRuler = detach_from<winrt::Windows::UI::Input::Inking::InkPresenterRuler>(this->shim().Create(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkPresenter const*>(&inkPresenter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkPresenterStencil> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkPresenterStencil>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkPresenterStencilKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsVisible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsVisible(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackgroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ForegroundColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Transform(winrt::Windows::Foundation::Numerics::float3x2* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3x2>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3x2>(this->shim().Transform());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Transform(winrt::Windows::Foundation::Numerics::float3x2 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Transform(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkRecognitionResult> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkRecognitionResult>
    {
        int32_t __stdcall get_BoundingRect(winrt::Windows::Foundation::Rect* boundingRect) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(boundingRect);
            typename D::abi_guard guard(this->shim());
            *boundingRect = detach_from<winrt::Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTextCandidates(void** textCandidates) noexcept final try
        {
            clear_abi(textCandidates);
            typename D::abi_guard guard(this->shim());
            *textCandidates = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetTextCandidates());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStrokes(void** strokes) noexcept final try
        {
            clear_abi(strokes);
            typename D::abi_guard guard(this->shim());
            *strokes = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>>(this->shim().GetStrokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkRecognizer> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkRecognizer>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkRecognizerContainer> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkRecognizerContainer>
    {
        int32_t __stdcall SetDefaultRecognizer(void* recognizer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDefaultRecognizer(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkRecognizer const*>(&recognizer));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RecognizeAsync(void* strokeCollection, int32_t recognitionTarget, void** recognitionResults) noexcept final try
        {
            clear_abi(recognitionResults);
            typename D::abi_guard guard(this->shim());
            *recognitionResults = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>>>(this->shim().RecognizeAsync(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkStrokeContainer const*>(&strokeCollection), *reinterpret_cast<winrt::Windows::UI::Input::Inking::InkRecognitionTarget const*>(&recognitionTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRecognizers(void** recognizerView) noexcept final try
        {
            clear_abi(recognizerView);
            typename D::abi_guard guard(this->shim());
            *recognizerView = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognizer>>(this->shim().GetRecognizers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStroke> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStroke>
    {
        int32_t __stdcall get_DrawingAttributes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkDrawingAttributes>(this->shim().DrawingAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DrawingAttributes(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DrawingAttributes(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkDrawingAttributes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BoundingRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Selected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Selected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Selected(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Selected(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Recognized(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Recognized());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRenderingSegments(void** renderingSegments) noexcept final try
        {
            clear_abi(renderingSegments);
            typename D::abi_guard guard(this->shim());
            *renderingSegments = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStrokeRenderingSegment>>(this->shim().GetRenderingSegments());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Clone(void** clonedStroke) noexcept final try
        {
            clear_abi(clonedStroke);
            typename D::abi_guard guard(this->shim());
            *clonedStroke = detach_from<winrt::Windows::UI::Input::Inking::InkStroke>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStroke2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStroke2>
    {
        int32_t __stdcall get_PointTransform(winrt::Windows::Foundation::Numerics::float3x2* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3x2>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3x2>(this->shim().PointTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointTransform(winrt::Windows::Foundation::Numerics::float3x2 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointTransform(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetInkPoints(void** inkPoints) noexcept final try
        {
            clear_abi(inkPoints);
            typename D::abi_guard guard(this->shim());
            *inkPoints = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkPoint>>(this->shim().GetInkPoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStroke3> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStroke3>
    {
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeStartedTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().StrokeStartedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeStartedTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeStartedTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StrokeDuration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().StrokeDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StrokeDuration(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeDuration(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStroke4> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStroke4>
    {
        int32_t __stdcall get_PointerId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().PointerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder>
    {
        int32_t __stdcall BeginStroke(void* pointerPoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BeginStroke(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendToStroke(void* pointerPoint, void** previousPointerPoint) noexcept final try
        {
            clear_abi(previousPointerPoint);
            typename D::abi_guard guard(this->shim());
            *previousPointerPoint = detach_from<winrt::Windows::UI::Input::PointerPoint>(this->shim().AppendToStroke(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EndStroke(void* pointerPoint, void** stroke) noexcept final try
        {
            clear_abi(stroke);
            typename D::abi_guard guard(this->shim());
            *stroke = detach_from<winrt::Windows::UI::Input::Inking::InkStroke>(this->shim().EndStroke(*reinterpret_cast<winrt::Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStroke(void* points, void** stroke) noexcept final try
        {
            clear_abi(stroke);
            typename D::abi_guard guard(this->shim());
            *stroke = detach_from<winrt::Windows::UI::Input::Inking::InkStroke>(this->shim().CreateStroke(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Point> const*>(&points)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDefaultDrawingAttributes(void* drawingAttributes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDefaultDrawingAttributes(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkDrawingAttributes const*>(&drawingAttributes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2>
    {
        int32_t __stdcall CreateStrokeFromInkPoints(void* inkPoints, winrt::Windows::Foundation::Numerics::float3x2 transform, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Inking::InkStroke>(this->shim().CreateStrokeFromInkPoints(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::Inking::InkPoint> const*>(&inkPoints), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3x2 const*>(&transform)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3>
    {
        int32_t __stdcall CreateStrokeFromInkPoints(void* inkPoints, winrt::Windows::Foundation::Numerics::float3x2 transform, void* strokeStartedTime, void* strokeDuration, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Inking::InkStroke>(this->shim().CreateStrokeFromInkPoints(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::Inking::InkPoint> const*>(&inkPoints), *reinterpret_cast<winrt::Windows::Foundation::Numerics::float3x2 const*>(&transform), *reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const*>(&strokeStartedTime), *reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&strokeDuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeContainer> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeContainer>
    {
        int32_t __stdcall get_BoundingRect(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddStroke(void* stroke) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddStroke(*reinterpret_cast<winrt::Windows::UI::Input::Inking::InkStroke const*>(&stroke));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteSelected(winrt::Windows::Foundation::Rect* invalidatedRect) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(invalidatedRect);
            typename D::abi_guard guard(this->shim());
            *invalidatedRect = detach_from<winrt::Windows::Foundation::Rect>(this->shim().DeleteSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveSelected(winrt::Windows::Foundation::Point translation, winrt::Windows::Foundation::Rect* invalidatedRectangle) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(invalidatedRectangle);
            typename D::abi_guard guard(this->shim());
            *invalidatedRectangle = detach_from<winrt::Windows::Foundation::Rect>(this->shim().MoveSelected(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&translation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SelectWithPolyLine(void* polyline, winrt::Windows::Foundation::Rect* invalidatedRectangle) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(invalidatedRectangle);
            typename D::abi_guard guard(this->shim());
            *invalidatedRectangle = detach_from<winrt::Windows::Foundation::Rect>(this->shim().SelectWithPolyLine(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Point> const*>(&polyline)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SelectWithLine(winrt::Windows::Foundation::Point from, winrt::Windows::Foundation::Point to, winrt::Windows::Foundation::Rect* invalidatedRectangle) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(invalidatedRectangle);
            typename D::abi_guard guard(this->shim());
            *invalidatedRectangle = detach_from<winrt::Windows::Foundation::Rect>(this->shim().SelectWithLine(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&from), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&to)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopySelectedToClipboard() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CopySelectedToClipboard();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PasteFromClipboard(winrt::Windows::Foundation::Point position, winrt::Windows::Foundation::Rect* invalidatedRectangle) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(invalidatedRectangle);
            typename D::abi_guard guard(this->shim());
            *invalidatedRectangle = detach_from<winrt::Windows::Foundation::Rect>(this->shim().PasteFromClipboard(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&position)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CanPasteFromClipboard(bool* canPaste) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *canPaste = detach_from<bool>(this->shim().CanPasteFromClipboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadAsync(void* inputStream, void** loadAction) noexcept final try
        {
            clear_abi(loadAction);
            typename D::abi_guard guard(this->shim());
            *loadAction = detach_from<winrt::Windows::Foundation::IAsyncActionWithProgress<uint64_t>>(this->shim().LoadAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&inputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SaveAsync(void* outputStream, void** outputStreamOperation) noexcept final try
        {
            clear_abi(outputStreamOperation);
            typename D::abi_guard guard(this->shim());
            *outputStreamOperation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SaveAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&outputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateRecognitionResults(void* recognitionResults) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateRecognitionResults(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult> const*>(&recognitionResults));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStrokes(void** strokeView) noexcept final try
        {
            clear_abi(strokeView);
            typename D::abi_guard guard(this->shim());
            *strokeView = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>>(this->shim().GetStrokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRecognitionResults(void** recognitionResults) noexcept final try
        {
            clear_abi(recognitionResults);
            typename D::abi_guard guard(this->shim());
            *recognitionResults = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkRecognitionResult>>(this->shim().GetRecognitionResults());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeContainer2> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeContainer2>
    {
        int32_t __stdcall AddStrokes(void* strokes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddStrokes(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Input::Inking::InkStroke> const*>(&strokes));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeContainer3> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeContainer3>
    {
        int32_t __stdcall SaveWithFormatAsync(void* outputStream, int32_t inkPersistenceFormat, void** outputStreamOperation) noexcept final try
        {
            clear_abi(outputStreamOperation);
            typename D::abi_guard guard(this->shim());
            *outputStreamOperation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SaveAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&outputStream), *reinterpret_cast<winrt::Windows::UI::Input::Inking::InkPersistenceFormat const*>(&inkPersistenceFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStrokeById(uint32_t id, void** stroke) noexcept final try
        {
            clear_abi(stroke);
            typename D::abi_guard guard(this->shim());
            *stroke = detach_from<winrt::Windows::UI::Input::Inking::InkStroke>(this->shim().GetStrokeById(id));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeInput> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeInput>
    {
        int32_t __stdcall add_StrokeStarted(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StrokeStarted(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeStarted(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_StrokeContinued(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeContinued(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StrokeContinued(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeContinued(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_StrokeEnded(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StrokeEnded(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeEnded(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_StrokeCanceled(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StrokeCanceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkStrokeInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StrokeCanceled(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StrokeCanceled(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_InkPresenter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkPresenter>(this->shim().InkPresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment>
    {
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BezierControlPoint1(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().BezierControlPoint1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BezierControlPoint2(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().BezierControlPoint2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pressure(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TiltX(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().TiltX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TiltY(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().TiltY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Twist(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().Twist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs>
    {
        int32_t __stdcall get_Strokes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>>(this->shim().Strokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs>
    {
        int32_t __stdcall get_Strokes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>>(this->shim().Strokes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkSynchronizer> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkSynchronizer>
    {
        int32_t __stdcall BeginDry(void** inkStrokes) noexcept final try
        {
            clear_abi(inkStrokes);
            typename D::abi_guard guard(this->shim());
            *inkStrokes = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Input::Inking::InkStroke>>(this->shim().BeginDry());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EndDry() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndDry();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IInkUnprocessedInput> : produce_base<D, winrt::Windows::UI::Input::Inking::IInkUnprocessedInput>
    {
        int32_t __stdcall add_PointerEntered(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerEntered(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerHovered(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerHovered(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerHovered(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerHovered(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerExited(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerExited(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerMoved(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerMoved(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerReleased(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerReleased(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerLost(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerLost(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::Inking::InkUnprocessedInput, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerLost(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_InkPresenter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::InkPresenter>(this->shim().InkPresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IPenAndInkSettings> : produce_base<D, winrt::Windows::UI::Input::Inking::IPenAndInkSettings>
    {
        int32_t __stdcall get_IsHandwritingDirectlyIntoTextFieldEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsHandwritingDirectlyIntoTextFieldEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PenHandedness(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::PenHandedness>(this->shim().PenHandedness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HandwritingLineHeight(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::Inking::HandwritingLineHeight>(this->shim().HandwritingLineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FontFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserConsentsToHandwritingTelemetryCollection(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UserConsentsToHandwritingTelemetryCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTouchHandwritingEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTouchHandwritingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IPenAndInkSettings2> : produce_base<D, winrt::Windows::UI::Input::Inking::IPenAndInkSettings2>
    {
        int32_t __stdcall SetPenHandedness(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPenHandedness(*reinterpret_cast<winrt::Windows::UI::Input::Inking::PenHandedness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Inking::IPenAndInkSettingsStatics> : produce_base<D, winrt::Windows::UI::Input::Inking::IPenAndInkSettingsStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Inking::PenAndInkSettings>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking
{
    inline InkDrawingAttributes::InkDrawingAttributes() :
        InkDrawingAttributes(impl::call_factory_cast<InkDrawingAttributes(*)(winrt::Windows::Foundation::IActivationFactory const&), InkDrawingAttributes>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InkDrawingAttributes>(); }))
    {
    }
    inline auto InkDrawingAttributes::CreateForPencil()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::Inking::InkDrawingAttributes(*)(IInkDrawingAttributesStatics const&), InkDrawingAttributes, IInkDrawingAttributesStatics>([](IInkDrawingAttributesStatics const& f) { return f.CreateForPencil(); });
    }
    inline InkManager::InkManager() :
        InkManager(impl::call_factory_cast<InkManager(*)(winrt::Windows::Foundation::IActivationFactory const&), InkManager>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InkManager>(); }))
    {
    }
    inline InkPoint::InkPoint(winrt::Windows::Foundation::Point const& position, float pressure) :
        InkPoint(impl::call_factory<InkPoint, IInkPointFactory>([&](IInkPointFactory const& f) { return f.CreateInkPoint(position, pressure); }))
    {
    }
    inline InkPoint::InkPoint(winrt::Windows::Foundation::Point const& position, float pressure, float tiltX, float tiltY, uint64_t timestamp) :
        InkPoint(impl::call_factory<InkPoint, IInkPointFactory2>([&](IInkPointFactory2 const& f) { return f.CreateInkPointWithTiltAndTimestamp(position, pressure, tiltX, tiltY, timestamp); }))
    {
    }
    inline InkPresenterProtractor::InkPresenterProtractor(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter) :
        InkPresenterProtractor(impl::call_factory<InkPresenterProtractor, IInkPresenterProtractorFactory>([&](IInkPresenterProtractorFactory const& f) { return f.Create(inkPresenter); }))
    {
    }
    inline InkPresenterRuler::InkPresenterRuler(winrt::Windows::UI::Input::Inking::InkPresenter const& inkPresenter) :
        InkPresenterRuler(impl::call_factory<InkPresenterRuler, IInkPresenterRulerFactory>([&](IInkPresenterRulerFactory const& f) { return f.Create(inkPresenter); }))
    {
    }
    inline InkRecognizerContainer::InkRecognizerContainer() :
        InkRecognizerContainer(impl::call_factory_cast<InkRecognizerContainer(*)(winrt::Windows::Foundation::IActivationFactory const&), InkRecognizerContainer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InkRecognizerContainer>(); }))
    {
    }
    inline InkStrokeBuilder::InkStrokeBuilder() :
        InkStrokeBuilder(impl::call_factory_cast<InkStrokeBuilder(*)(winrt::Windows::Foundation::IActivationFactory const&), InkStrokeBuilder>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InkStrokeBuilder>(); }))
    {
    }
    inline InkStrokeContainer::InkStrokeContainer() :
        InkStrokeContainer(impl::call_factory_cast<InkStrokeContainer(*)(winrt::Windows::Foundation::IActivationFactory const&), InkStrokeContainer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InkStrokeContainer>(); }))
    {
    }
    inline auto PenAndInkSettings::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Input::Inking::PenAndInkSettings(*)(IPenAndInkSettingsStatics const&), PenAndInkSettings, IPenAndInkSettingsStatics>([](IPenAndInkSettingsStatics const& f) { return f.GetDefault(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributes5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributesPencilProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkDrawingAttributesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkInputConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkInputConfiguration2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkInputProcessingConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkModelerAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkModelerAttributes2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPoint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPoint2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPointFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPointFactory2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenter3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterProtractor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterProtractorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterRuler> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterRuler2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterRulerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkPresenterStencil> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkRecognitionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkRecognizerContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStroke> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStroke2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStroke3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStroke4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeBuilder3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeContainer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeContainer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeInput> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokeRenderingSegment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokesCollectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkStrokesErasedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkSynchronizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IInkUnprocessedInput> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IPenAndInkSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IPenAndInkSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::IPenAndInkSettingsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkDrawingAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkDrawingAttributesPencilProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkInputConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkInputProcessingConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkModelerAttributes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkPoint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkPresenter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkPresenterProtractor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkPresenterRuler> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkRecognitionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkRecognizerContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkStroke> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeBuilder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeContainer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeInput> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokeRenderingSegment> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokesCollectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkStrokesErasedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkSynchronizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::InkUnprocessedInput> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Inking::PenAndInkSettings> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
