// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Spatial_1_H
#define WINRT_Windows_UI_Input_Spatial_1_H
#include "winrt/impl/Windows.UI.Input.Spatial.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input::Spatial
{
    struct __declspec(empty_bases) ISpatialGestureRecognizer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialGestureRecognizer>
    {
        ISpatialGestureRecognizer(std::nullptr_t = nullptr) noexcept {}
        ISpatialGestureRecognizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialGestureRecognizerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialGestureRecognizerFactory>
    {
        ISpatialGestureRecognizerFactory(std::nullptr_t = nullptr) noexcept {}
        ISpatialGestureRecognizerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialHoldCanceledEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialHoldCanceledEventArgs>
    {
        ISpatialHoldCanceledEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialHoldCanceledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialHoldCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialHoldCompletedEventArgs>
    {
        ISpatialHoldCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialHoldCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialHoldStartedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialHoldStartedEventArgs>
    {
        ISpatialHoldStartedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialHoldStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteraction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteraction>
    {
        ISpatialInteraction(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteraction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionController>
    {
        ISpatialInteractionController(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionController2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionController2>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController>
    {
        ISpatialInteractionController2(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionController2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionController3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionController3>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController, winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2>
    {
        ISpatialInteractionController3(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionController3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionControllerProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionControllerProperties>
    {
        ISpatialInteractionControllerProperties(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionControllerProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionDetectedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionDetectedEventArgs>
    {
        ISpatialInteractionDetectedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionDetectedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionDetectedEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionDetectedEventArgs2>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs>
    {
        ISpatialInteractionDetectedEventArgs2(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionDetectedEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionManager>
    {
        ISpatialInteractionManager(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionManagerStatics>
    {
        ISpatialInteractionManagerStatics(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionManagerStatics2>
    {
        ISpatialInteractionManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSource>
    {
        ISpatialInteractionSource(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSource2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSource2>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource>
    {
        ISpatialInteractionSource2(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSource2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSource3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSource3>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2>
    {
        ISpatialInteractionSource3(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSource3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSource4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSource4>
    {
        ISpatialInteractionSource4(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSource4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceEventArgs>
    {
        ISpatialInteractionSourceEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceEventArgs2>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs>
    {
        ISpatialInteractionSourceEventArgs2(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceLocation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceLocation>
    {
        ISpatialInteractionSourceLocation(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceLocation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceLocation2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceLocation2>
    {
        ISpatialInteractionSourceLocation2(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceLocation2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceLocation3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceLocation3>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2>
    {
        ISpatialInteractionSourceLocation3(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceLocation3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceProperties>
    {
        ISpatialInteractionSourceProperties(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceState :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceState>
    {
        ISpatialInteractionSourceState(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceState(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceState2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceState2>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState>
    {
        ISpatialInteractionSourceState2(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceState2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialInteractionSourceState3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialInteractionSourceState3>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState, winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2>
    {
        ISpatialInteractionSourceState3(std::nullptr_t = nullptr) noexcept {}
        ISpatialInteractionSourceState3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialManipulationCanceledEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialManipulationCanceledEventArgs>
    {
        ISpatialManipulationCanceledEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialManipulationCanceledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialManipulationCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialManipulationCompletedEventArgs>
    {
        ISpatialManipulationCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialManipulationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialManipulationDelta :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialManipulationDelta>
    {
        ISpatialManipulationDelta(std::nullptr_t = nullptr) noexcept {}
        ISpatialManipulationDelta(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialManipulationStartedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialManipulationStartedEventArgs>
    {
        ISpatialManipulationStartedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialManipulationStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialManipulationUpdatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialManipulationUpdatedEventArgs>
    {
        ISpatialManipulationUpdatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialManipulationUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialNavigationCanceledEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialNavigationCanceledEventArgs>
    {
        ISpatialNavigationCanceledEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialNavigationCanceledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialNavigationCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialNavigationCompletedEventArgs>
    {
        ISpatialNavigationCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialNavigationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialNavigationStartedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialNavigationStartedEventArgs>
    {
        ISpatialNavigationStartedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialNavigationStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialNavigationUpdatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialNavigationUpdatedEventArgs>
    {
        ISpatialNavigationUpdatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialNavigationUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialPointerInteractionSourcePose :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialPointerInteractionSourcePose>
    {
        ISpatialPointerInteractionSourcePose(std::nullptr_t = nullptr) noexcept {}
        ISpatialPointerInteractionSourcePose(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialPointerInteractionSourcePose2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialPointerInteractionSourcePose2>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2, winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose>
    {
        ISpatialPointerInteractionSourcePose2(std::nullptr_t = nullptr) noexcept {}
        ISpatialPointerInteractionSourcePose2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialPointerPose :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialPointerPose>
    {
        ISpatialPointerPose(std::nullptr_t = nullptr) noexcept {}
        ISpatialPointerPose(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialPointerPose2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialPointerPose2>,
        impl::require<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2, winrt::Windows::UI::Input::Spatial::ISpatialPointerPose>
    {
        ISpatialPointerPose2(std::nullptr_t = nullptr) noexcept {}
        ISpatialPointerPose2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialPointerPose3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialPointerPose3>
    {
        ISpatialPointerPose3(std::nullptr_t = nullptr) noexcept {}
        ISpatialPointerPose3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialPointerPoseStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialPointerPoseStatics>
    {
        ISpatialPointerPoseStatics(std::nullptr_t = nullptr) noexcept {}
        ISpatialPointerPoseStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialRecognitionEndedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialRecognitionEndedEventArgs>
    {
        ISpatialRecognitionEndedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialRecognitionEndedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialRecognitionStartedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialRecognitionStartedEventArgs>
    {
        ISpatialRecognitionStartedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialRecognitionStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialTappedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialTappedEventArgs>
    {
        ISpatialTappedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ISpatialTappedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
