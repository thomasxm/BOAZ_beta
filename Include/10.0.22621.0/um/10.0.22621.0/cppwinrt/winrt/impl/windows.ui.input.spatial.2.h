// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Spatial_2_H
#define WINRT_Windows_UI_Input_Spatial_2_H
#include "winrt/impl/Windows.Perception.1.h"
#include "winrt/impl/Windows.Perception.Spatial.1.h"
#include "winrt/impl/Windows.UI.Input.Spatial.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Spatial
{
    struct __declspec(empty_bases) SpatialGestureRecognizer : winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer
    {
        SpatialGestureRecognizer(std::nullptr_t) noexcept {}
        SpatialGestureRecognizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer(ptr, take_ownership_from_abi) {}
        explicit SpatialGestureRecognizer(winrt::Windows::UI::Input::Spatial::SpatialGestureSettings const& settings);
    };
    struct __declspec(empty_bases) SpatialHoldCanceledEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs
    {
        SpatialHoldCanceledEventArgs(std::nullptr_t) noexcept {}
        SpatialHoldCanceledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialHoldCompletedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs
    {
        SpatialHoldCompletedEventArgs(std::nullptr_t) noexcept {}
        SpatialHoldCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialHoldStartedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs
    {
        SpatialHoldStartedEventArgs(std::nullptr_t) noexcept {}
        SpatialHoldStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteraction : winrt::Windows::UI::Input::Spatial::ISpatialInteraction
    {
        SpatialInteraction(std::nullptr_t) noexcept {}
        SpatialInteraction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteraction(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionController : winrt::Windows::UI::Input::Spatial::ISpatialInteractionController,
        impl::require<SpatialInteractionController, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3>
    {
        SpatialInteractionController(std::nullptr_t) noexcept {}
        SpatialInteractionController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionController(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionControllerProperties : winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties
    {
        SpatialInteractionControllerProperties(std::nullptr_t) noexcept {}
        SpatialInteractionControllerProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionDetectedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs,
        impl::require<SpatialInteractionDetectedEventArgs, winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2>
    {
        SpatialInteractionDetectedEventArgs(std::nullptr_t) noexcept {}
        SpatialInteractionDetectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionManager : winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager
    {
        SpatialInteractionManager(std::nullptr_t) noexcept {}
        SpatialInteractionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
        static auto IsSourceKindSupported(winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceKind const& kind);
    };
    struct __declspec(empty_bases) SpatialInteractionSource : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource,
        impl::require<SpatialInteractionSource, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4>
    {
        SpatialInteractionSource(std::nullptr_t) noexcept {}
        SpatialInteractionSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionSourceEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs,
        impl::require<SpatialInteractionSourceEventArgs, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2>
    {
        SpatialInteractionSourceEventArgs(std::nullptr_t) noexcept {}
        SpatialInteractionSourceEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionSourceLocation : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation,
        impl::require<SpatialInteractionSourceLocation, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3>
    {
        SpatialInteractionSourceLocation(std::nullptr_t) noexcept {}
        SpatialInteractionSourceLocation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionSourceProperties : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties
    {
        SpatialInteractionSourceProperties(std::nullptr_t) noexcept {}
        SpatialInteractionSourceProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialInteractionSourceState : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState,
        impl::require<SpatialInteractionSourceState, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3>
    {
        SpatialInteractionSourceState(std::nullptr_t) noexcept {}
        SpatialInteractionSourceState(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialManipulationCanceledEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs
    {
        SpatialManipulationCanceledEventArgs(std::nullptr_t) noexcept {}
        SpatialManipulationCanceledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialManipulationCompletedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs
    {
        SpatialManipulationCompletedEventArgs(std::nullptr_t) noexcept {}
        SpatialManipulationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialManipulationDelta : winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta
    {
        SpatialManipulationDelta(std::nullptr_t) noexcept {}
        SpatialManipulationDelta(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialManipulationStartedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs
    {
        SpatialManipulationStartedEventArgs(std::nullptr_t) noexcept {}
        SpatialManipulationStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialManipulationUpdatedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs
    {
        SpatialManipulationUpdatedEventArgs(std::nullptr_t) noexcept {}
        SpatialManipulationUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialNavigationCanceledEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs
    {
        SpatialNavigationCanceledEventArgs(std::nullptr_t) noexcept {}
        SpatialNavigationCanceledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialNavigationCompletedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs
    {
        SpatialNavigationCompletedEventArgs(std::nullptr_t) noexcept {}
        SpatialNavigationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialNavigationStartedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs
    {
        SpatialNavigationStartedEventArgs(std::nullptr_t) noexcept {}
        SpatialNavigationStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialNavigationUpdatedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs
    {
        SpatialNavigationUpdatedEventArgs(std::nullptr_t) noexcept {}
        SpatialNavigationUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialPointerInteractionSourcePose : winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose,
        impl::require<SpatialPointerInteractionSourcePose, winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2>
    {
        SpatialPointerInteractionSourcePose(std::nullptr_t) noexcept {}
        SpatialPointerInteractionSourcePose(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialPointerPose : winrt::Windows::UI::Input::Spatial::ISpatialPointerPose,
        impl::require<SpatialPointerPose, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3>
    {
        SpatialPointerPose(std::nullptr_t) noexcept {}
        SpatialPointerPose(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialPointerPose(ptr, take_ownership_from_abi) {}
        static auto TryGetAtTimestamp(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, winrt::Windows::Perception::PerceptionTimestamp const& timestamp);
    };
    struct __declspec(empty_bases) SpatialRecognitionEndedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs
    {
        SpatialRecognitionEndedEventArgs(std::nullptr_t) noexcept {}
        SpatialRecognitionEndedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialRecognitionStartedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs
    {
        SpatialRecognitionStartedEventArgs(std::nullptr_t) noexcept {}
        SpatialRecognitionStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpatialTappedEventArgs : winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs
    {
        SpatialTappedEventArgs(std::nullptr_t) noexcept {}
        SpatialTappedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
