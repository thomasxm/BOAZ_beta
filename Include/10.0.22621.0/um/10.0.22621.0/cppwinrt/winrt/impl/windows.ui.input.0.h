// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_0_H
#define WINRT_Windows_UI_Input_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Haptics
{
    struct SimpleHapticsController;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Input
{
    struct PointerDevice;
    enum class PointerDeviceType : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename T> struct __declspec(empty_bases) IReference;
    struct Point;
    struct Rect;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct RandomAccessStreamReference;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct DispatcherQueue;
}
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    struct KeyEventArgs;
}
WINRT_EXPORT namespace winrt::Windows::UI::Input
{
    enum class CrossSlidingState : int32_t
    {
        Started = 0,
        Dragging = 1,
        Selecting = 2,
        SelectSpeedBumping = 3,
        SpeedBumping = 4,
        Rearranging = 5,
        Completed = 6,
    };
    enum class DraggingState : int32_t
    {
        Started = 0,
        Continuing = 1,
        Completed = 2,
    };
    enum class EdgeGestureKind : int32_t
    {
        Touch = 0,
        Keyboard = 1,
        Mouse = 2,
    };
    enum class GazeInputAccessStatus : int32_t
    {
        Unspecified = 0,
        Allowed = 1,
        DeniedByUser = 2,
        DeniedBySystem = 3,
    };
    enum class GestureSettings : uint32_t
    {
        None = 0,
        Tap = 0x1,
        DoubleTap = 0x2,
        Hold = 0x4,
        HoldWithMouse = 0x8,
        RightTap = 0x10,
        Drag = 0x20,
        ManipulationTranslateX = 0x40,
        ManipulationTranslateY = 0x80,
        ManipulationTranslateRailsX = 0x100,
        ManipulationTranslateRailsY = 0x200,
        ManipulationRotate = 0x400,
        ManipulationScale = 0x800,
        ManipulationTranslateInertia = 0x1000,
        ManipulationRotateInertia = 0x2000,
        ManipulationScaleInertia = 0x4000,
        CrossSlide = 0x8000,
        ManipulationMultipleFingerPanning = 0x10000,
    };
    enum class HoldingState : int32_t
    {
        Started = 0,
        Completed = 1,
        Canceled = 2,
    };
    enum class InputActivationState : int32_t
    {
        None = 0,
        Deactivated = 1,
        ActivatedNotForeground = 2,
        ActivatedInForeground = 3,
    };
    enum class PointerUpdateKind : int32_t
    {
        Other = 0,
        LeftButtonPressed = 1,
        LeftButtonReleased = 2,
        RightButtonPressed = 3,
        RightButtonReleased = 4,
        MiddleButtonPressed = 5,
        MiddleButtonReleased = 6,
        XButton1Pressed = 7,
        XButton1Released = 8,
        XButton2Pressed = 9,
        XButton2Released = 10,
    };
    enum class RadialControllerMenuKnownIcon : int32_t
    {
        Scroll = 0,
        Zoom = 1,
        UndoRedo = 2,
        Volume = 3,
        NextPreviousTrack = 4,
        Ruler = 5,
        InkColor = 6,
        InkThickness = 7,
        PenType = 8,
    };
    enum class RadialControllerSystemMenuItemKind : int32_t
    {
        Scroll = 0,
        Zoom = 1,
        UndoRedo = 2,
        Volume = 3,
        NextPreviousTrack = 4,
    };
    struct IAttachableInputObject;
    struct IAttachableInputObjectFactory;
    struct ICrossSlidingEventArgs;
    struct ICrossSlidingEventArgs2;
    struct IDraggingEventArgs;
    struct IDraggingEventArgs2;
    struct IEdgeGesture;
    struct IEdgeGestureEventArgs;
    struct IEdgeGestureStatics;
    struct IGestureRecognizer;
    struct IGestureRecognizer2;
    struct IHoldingEventArgs;
    struct IHoldingEventArgs2;
    struct IInputActivationListener;
    struct IInputActivationListenerActivationChangedEventArgs;
    struct IKeyboardDeliveryInterceptor;
    struct IKeyboardDeliveryInterceptorStatics;
    struct IManipulationCompletedEventArgs;
    struct IManipulationCompletedEventArgs2;
    struct IManipulationInertiaStartingEventArgs;
    struct IManipulationInertiaStartingEventArgs2;
    struct IManipulationStartedEventArgs;
    struct IManipulationStartedEventArgs2;
    struct IManipulationUpdatedEventArgs;
    struct IManipulationUpdatedEventArgs2;
    struct IMouseWheelParameters;
    struct IPointerPoint;
    struct IPointerPointProperties;
    struct IPointerPointProperties2;
    struct IPointerPointStatics;
    struct IPointerPointTransform;
    struct IPointerVisualizationSettings;
    struct IPointerVisualizationSettingsStatics;
    struct IRadialController;
    struct IRadialController2;
    struct IRadialControllerButtonClickedEventArgs;
    struct IRadialControllerButtonClickedEventArgs2;
    struct IRadialControllerButtonHoldingEventArgs;
    struct IRadialControllerButtonPressedEventArgs;
    struct IRadialControllerButtonReleasedEventArgs;
    struct IRadialControllerConfiguration;
    struct IRadialControllerConfiguration2;
    struct IRadialControllerConfigurationStatics;
    struct IRadialControllerConfigurationStatics2;
    struct IRadialControllerControlAcquiredEventArgs;
    struct IRadialControllerControlAcquiredEventArgs2;
    struct IRadialControllerMenu;
    struct IRadialControllerMenuItem;
    struct IRadialControllerMenuItemStatics;
    struct IRadialControllerMenuItemStatics2;
    struct IRadialControllerRotationChangedEventArgs;
    struct IRadialControllerRotationChangedEventArgs2;
    struct IRadialControllerScreenContact;
    struct IRadialControllerScreenContactContinuedEventArgs;
    struct IRadialControllerScreenContactContinuedEventArgs2;
    struct IRadialControllerScreenContactEndedEventArgs;
    struct IRadialControllerScreenContactStartedEventArgs;
    struct IRadialControllerScreenContactStartedEventArgs2;
    struct IRadialControllerStatics;
    struct IRightTappedEventArgs;
    struct IRightTappedEventArgs2;
    struct ISystemButtonEventController;
    struct ISystemButtonEventControllerStatics;
    struct ISystemFunctionButtonEventArgs;
    struct ISystemFunctionLockChangedEventArgs;
    struct ISystemFunctionLockIndicatorChangedEventArgs;
    struct ITappedEventArgs;
    struct ITappedEventArgs2;
    struct AttachableInputObject;
    struct CrossSlidingEventArgs;
    struct DraggingEventArgs;
    struct EdgeGesture;
    struct EdgeGestureEventArgs;
    struct GestureRecognizer;
    struct HoldingEventArgs;
    struct InputActivationListener;
    struct InputActivationListenerActivationChangedEventArgs;
    struct KeyboardDeliveryInterceptor;
    struct ManipulationCompletedEventArgs;
    struct ManipulationInertiaStartingEventArgs;
    struct ManipulationStartedEventArgs;
    struct ManipulationUpdatedEventArgs;
    struct MouseWheelParameters;
    struct PointerPoint;
    struct PointerPointProperties;
    struct PointerVisualizationSettings;
    struct RadialController;
    struct RadialControllerButtonClickedEventArgs;
    struct RadialControllerButtonHoldingEventArgs;
    struct RadialControllerButtonPressedEventArgs;
    struct RadialControllerButtonReleasedEventArgs;
    struct RadialControllerConfiguration;
    struct RadialControllerControlAcquiredEventArgs;
    struct RadialControllerMenu;
    struct RadialControllerMenuItem;
    struct RadialControllerRotationChangedEventArgs;
    struct RadialControllerScreenContact;
    struct RadialControllerScreenContactContinuedEventArgs;
    struct RadialControllerScreenContactEndedEventArgs;
    struct RadialControllerScreenContactStartedEventArgs;
    struct RightTappedEventArgs;
    struct SystemButtonEventController;
    struct SystemFunctionButtonEventArgs;
    struct SystemFunctionLockChangedEventArgs;
    struct SystemFunctionLockIndicatorChangedEventArgs;
    struct TappedEventArgs;
    struct CrossSlideThresholds;
    struct ManipulationDelta;
    struct ManipulationVelocities;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::Input::IAttachableInputObject>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IAttachableInputObjectFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ICrossSlidingEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ICrossSlidingEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IDraggingEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IDraggingEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IEdgeGesture>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IEdgeGestureEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IEdgeGestureStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IGestureRecognizer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IGestureRecognizer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IHoldingEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IHoldingEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IInputActivationListener>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationCompletedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationStartedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationStartedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IMouseWheelParameters>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IPointerPoint>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IPointerPointProperties>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IPointerPointProperties2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IPointerPointStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IPointerPointTransform>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IPointerVisualizationSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialController>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialController2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerConfiguration>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerConfiguration2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerMenu>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerMenuItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerScreenContact>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRadialControllerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRightTappedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::IRightTappedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ISystemButtonEventController>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ISystemButtonEventControllerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ITappedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::ITappedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Input::AttachableInputObject>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::CrossSlidingEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::DraggingEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::EdgeGesture>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::EdgeGestureEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::GestureRecognizer>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::HoldingEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::InputActivationListener>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::ManipulationCompletedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::ManipulationStartedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::ManipulationUpdatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::MouseWheelParameters>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::PointerPoint>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::PointerPointProperties>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::PointerVisualizationSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialController>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerConfiguration>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerMenu>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerMenuItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerScreenContact>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerScreenContactEndedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::RightTappedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::SystemButtonEventController>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::SystemFunctionButtonEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::TappedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Input::CrossSlidingState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::DraggingState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::EdgeGestureKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::GazeInputAccessStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::GestureSettings>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::HoldingState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::InputActivationState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::PointerUpdateKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerMenuKnownIcon>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Input::CrossSlideThresholds>{ using type = struct_category<float, float, float, float>; };
    template <> struct category<winrt::Windows::UI::Input::ManipulationDelta>{ using type = struct_category<winrt::Windows::Foundation::Point, float, float, float>; };
    template <> struct category<winrt::Windows::UI::Input::ManipulationVelocities>{ using type = struct_category<winrt::Windows::Foundation::Point, float, float>; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::AttachableInputObject> = L"Windows.UI.Input.AttachableInputObject";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::CrossSlidingEventArgs> = L"Windows.UI.Input.CrossSlidingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::DraggingEventArgs> = L"Windows.UI.Input.DraggingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::EdgeGesture> = L"Windows.UI.Input.EdgeGesture";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::EdgeGestureEventArgs> = L"Windows.UI.Input.EdgeGestureEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::GestureRecognizer> = L"Windows.UI.Input.GestureRecognizer";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::HoldingEventArgs> = L"Windows.UI.Input.HoldingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::InputActivationListener> = L"Windows.UI.Input.InputActivationListener";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> = L"Windows.UI.Input.InputActivationListenerActivationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor> = L"Windows.UI.Input.KeyboardDeliveryInterceptor";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ManipulationCompletedEventArgs> = L"Windows.UI.Input.ManipulationCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> = L"Windows.UI.Input.ManipulationInertiaStartingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ManipulationStartedEventArgs> = L"Windows.UI.Input.ManipulationStartedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> = L"Windows.UI.Input.ManipulationUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::MouseWheelParameters> = L"Windows.UI.Input.MouseWheelParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::PointerPoint> = L"Windows.UI.Input.PointerPoint";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::PointerPointProperties> = L"Windows.UI.Input.PointerPointProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::PointerVisualizationSettings> = L"Windows.UI.Input.PointerVisualizationSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialController> = L"Windows.UI.Input.RadialController";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> = L"Windows.UI.Input.RadialControllerButtonClickedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> = L"Windows.UI.Input.RadialControllerButtonHoldingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> = L"Windows.UI.Input.RadialControllerButtonPressedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> = L"Windows.UI.Input.RadialControllerButtonReleasedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerConfiguration> = L"Windows.UI.Input.RadialControllerConfiguration";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> = L"Windows.UI.Input.RadialControllerControlAcquiredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerMenu> = L"Windows.UI.Input.RadialControllerMenu";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerMenuItem> = L"Windows.UI.Input.RadialControllerMenuItem";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> = L"Windows.UI.Input.RadialControllerRotationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerScreenContact> = L"Windows.UI.Input.RadialControllerScreenContact";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> = L"Windows.UI.Input.RadialControllerScreenContactContinuedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerScreenContactEndedEventArgs> = L"Windows.UI.Input.RadialControllerScreenContactEndedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> = L"Windows.UI.Input.RadialControllerScreenContactStartedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RightTappedEventArgs> = L"Windows.UI.Input.RightTappedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::SystemButtonEventController> = L"Windows.UI.Input.SystemButtonEventController";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> = L"Windows.UI.Input.SystemFunctionButtonEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs> = L"Windows.UI.Input.SystemFunctionLockChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs> = L"Windows.UI.Input.SystemFunctionLockIndicatorChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::TappedEventArgs> = L"Windows.UI.Input.TappedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::CrossSlidingState> = L"Windows.UI.Input.CrossSlidingState";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::DraggingState> = L"Windows.UI.Input.DraggingState";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::EdgeGestureKind> = L"Windows.UI.Input.EdgeGestureKind";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::GazeInputAccessStatus> = L"Windows.UI.Input.GazeInputAccessStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::GestureSettings> = L"Windows.UI.Input.GestureSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::HoldingState> = L"Windows.UI.Input.HoldingState";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::InputActivationState> = L"Windows.UI.Input.InputActivationState";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::PointerUpdateKind> = L"Windows.UI.Input.PointerUpdateKind";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerMenuKnownIcon> = L"Windows.UI.Input.RadialControllerMenuKnownIcon";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind> = L"Windows.UI.Input.RadialControllerSystemMenuItemKind";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::CrossSlideThresholds> = L"Windows.UI.Input.CrossSlideThresholds";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ManipulationDelta> = L"Windows.UI.Input.ManipulationDelta";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ManipulationVelocities> = L"Windows.UI.Input.ManipulationVelocities";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IAttachableInputObject> = L"Windows.UI.Input.IAttachableInputObject";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IAttachableInputObjectFactory> = L"Windows.UI.Input.IAttachableInputObjectFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ICrossSlidingEventArgs> = L"Windows.UI.Input.ICrossSlidingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ICrossSlidingEventArgs2> = L"Windows.UI.Input.ICrossSlidingEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IDraggingEventArgs> = L"Windows.UI.Input.IDraggingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IDraggingEventArgs2> = L"Windows.UI.Input.IDraggingEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IEdgeGesture> = L"Windows.UI.Input.IEdgeGesture";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IEdgeGestureEventArgs> = L"Windows.UI.Input.IEdgeGestureEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IEdgeGestureStatics> = L"Windows.UI.Input.IEdgeGestureStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IGestureRecognizer> = L"Windows.UI.Input.IGestureRecognizer";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IGestureRecognizer2> = L"Windows.UI.Input.IGestureRecognizer2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IHoldingEventArgs> = L"Windows.UI.Input.IHoldingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IHoldingEventArgs2> = L"Windows.UI.Input.IHoldingEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IInputActivationListener> = L"Windows.UI.Input.IInputActivationListener";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs> = L"Windows.UI.Input.IInputActivationListenerActivationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor> = L"Windows.UI.Input.IKeyboardDeliveryInterceptor";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics> = L"Windows.UI.Input.IKeyboardDeliveryInterceptorStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationCompletedEventArgs> = L"Windows.UI.Input.IManipulationCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationCompletedEventArgs2> = L"Windows.UI.Input.IManipulationCompletedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs> = L"Windows.UI.Input.IManipulationInertiaStartingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2> = L"Windows.UI.Input.IManipulationInertiaStartingEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationStartedEventArgs> = L"Windows.UI.Input.IManipulationStartedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationStartedEventArgs2> = L"Windows.UI.Input.IManipulationStartedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs> = L"Windows.UI.Input.IManipulationUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2> = L"Windows.UI.Input.IManipulationUpdatedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IMouseWheelParameters> = L"Windows.UI.Input.IMouseWheelParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IPointerPoint> = L"Windows.UI.Input.IPointerPoint";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IPointerPointProperties> = L"Windows.UI.Input.IPointerPointProperties";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IPointerPointProperties2> = L"Windows.UI.Input.IPointerPointProperties2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IPointerPointStatics> = L"Windows.UI.Input.IPointerPointStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IPointerPointTransform> = L"Windows.UI.Input.IPointerPointTransform";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IPointerVisualizationSettings> = L"Windows.UI.Input.IPointerVisualizationSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics> = L"Windows.UI.Input.IPointerVisualizationSettingsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialController> = L"Windows.UI.Input.IRadialController";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialController2> = L"Windows.UI.Input.IRadialController2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs> = L"Windows.UI.Input.IRadialControllerButtonClickedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2> = L"Windows.UI.Input.IRadialControllerButtonClickedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs> = L"Windows.UI.Input.IRadialControllerButtonHoldingEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs> = L"Windows.UI.Input.IRadialControllerButtonPressedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs> = L"Windows.UI.Input.IRadialControllerButtonReleasedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerConfiguration> = L"Windows.UI.Input.IRadialControllerConfiguration";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerConfiguration2> = L"Windows.UI.Input.IRadialControllerConfiguration2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics> = L"Windows.UI.Input.IRadialControllerConfigurationStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2> = L"Windows.UI.Input.IRadialControllerConfigurationStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs> = L"Windows.UI.Input.IRadialControllerControlAcquiredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2> = L"Windows.UI.Input.IRadialControllerControlAcquiredEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerMenu> = L"Windows.UI.Input.IRadialControllerMenu";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerMenuItem> = L"Windows.UI.Input.IRadialControllerMenuItem";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics> = L"Windows.UI.Input.IRadialControllerMenuItemStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2> = L"Windows.UI.Input.IRadialControllerMenuItemStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs> = L"Windows.UI.Input.IRadialControllerRotationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2> = L"Windows.UI.Input.IRadialControllerRotationChangedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerScreenContact> = L"Windows.UI.Input.IRadialControllerScreenContact";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs> = L"Windows.UI.Input.IRadialControllerScreenContactContinuedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2> = L"Windows.UI.Input.IRadialControllerScreenContactContinuedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs> = L"Windows.UI.Input.IRadialControllerScreenContactEndedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs> = L"Windows.UI.Input.IRadialControllerScreenContactStartedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2> = L"Windows.UI.Input.IRadialControllerScreenContactStartedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRadialControllerStatics> = L"Windows.UI.Input.IRadialControllerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRightTappedEventArgs> = L"Windows.UI.Input.IRightTappedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::IRightTappedEventArgs2> = L"Windows.UI.Input.IRightTappedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ISystemButtonEventController> = L"Windows.UI.Input.ISystemButtonEventController";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ISystemButtonEventControllerStatics> = L"Windows.UI.Input.ISystemButtonEventControllerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs> = L"Windows.UI.Input.ISystemFunctionButtonEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs> = L"Windows.UI.Input.ISystemFunctionLockChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs> = L"Windows.UI.Input.ISystemFunctionLockIndicatorChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ITappedEventArgs> = L"Windows.UI.Input.ITappedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Input::ITappedEventArgs2> = L"Windows.UI.Input.ITappedEventArgs2";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IAttachableInputObject>{ 0x9B822734,0xA3C1,0x542A,{ 0xB2,0xF4,0x0E,0x32,0xB7,0x73,0xFB,0x07 } }; // 9B822734-A3C1-542A-B2F4-0E32B773FB07
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IAttachableInputObjectFactory>{ 0xA4C54C4E,0x42BC,0x58FA,{ 0xA6,0x40,0xEA,0x15,0x16,0xF4,0xC0,0x6B } }; // A4C54C4E-42BC-58FA-A640-EA1516F4C06B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ICrossSlidingEventArgs>{ 0xE9374738,0x6F88,0x41D9,{ 0x87,0x20,0x78,0xE0,0x8E,0x39,0x83,0x49 } }; // E9374738-6F88-41D9-8720-78E08E398349
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ICrossSlidingEventArgs2>{ 0xEEFB7D48,0xC070,0x59F3,{ 0x8D,0xAB,0xBC,0xAF,0x62,0x1D,0x86,0x87 } }; // EEFB7D48-C070-59F3-8DAB-BCAF621D8687
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IDraggingEventArgs>{ 0x1C905384,0x083C,0x4BD3,{ 0xB5,0x59,0x17,0x9C,0xDD,0xEB,0x33,0xEC } }; // 1C905384-083C-4BD3-B559-179CDDEB33EC
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IDraggingEventArgs2>{ 0x71EFDBF9,0x382A,0x55CA,{ 0xB4,0xB9,0x00,0x81,0x23,0xC1,0xBF,0x1A } }; // 71EFDBF9-382A-55CA-B4B9-008123C1BF1A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IEdgeGesture>{ 0x580D5292,0x2AB1,0x49AA,{ 0xA7,0xF0,0x33,0xBD,0x3F,0x8D,0xF9,0xF1 } }; // 580D5292-2AB1-49AA-A7F0-33BD3F8DF9F1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IEdgeGestureEventArgs>{ 0x44FA4A24,0x2D09,0x42E1,{ 0x8B,0x5E,0x36,0x82,0x08,0x79,0x6A,0x4C } }; // 44FA4A24-2D09-42E1-8B5E-368208796A4C
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IEdgeGestureStatics>{ 0xBC6A8519,0x18EE,0x4043,{ 0x98,0x39,0x4F,0xC5,0x84,0xD6,0x0A,0x14 } }; // BC6A8519-18EE-4043-9839-4FC584D60A14
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IGestureRecognizer>{ 0xB47A37BF,0x3D6B,0x4F88,{ 0x83,0xE8,0x6D,0xCB,0x40,0x12,0xFF,0xB0 } }; // B47A37BF-3D6B-4F88-83E8-6DCB4012FFB0
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IGestureRecognizer2>{ 0xD646097F,0x6EF7,0x5746,{ 0x8B,0xA8,0x8F,0xF2,0x20,0x6E,0x6F,0x3B } }; // D646097F-6EF7-5746-8BA8-8FF2206E6F3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IHoldingEventArgs>{ 0x2BF755C5,0xE799,0x41B4,{ 0xBB,0x40,0x24,0x2F,0x40,0x95,0x9B,0x71 } }; // 2BF755C5-E799-41B4-BB40-242F40959B71
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IHoldingEventArgs2>{ 0x141DA9EA,0x4C79,0x5674,{ 0xAF,0xEA,0x49,0x3F,0xDE,0xB9,0x1F,0x19 } }; // 141DA9EA-4C79-5674-AFEA-493FDEB91F19
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IInputActivationListener>{ 0x5D6D4ED2,0x28C7,0x5AE3,{ 0xAA,0x74,0xC9,0x18,0xA9,0xF2,0x43,0xCA } }; // 5D6D4ED2-28C7-5AE3-AA74-C918A9F243CA
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs>{ 0x7699B465,0x1DCF,0x5791,{ 0xB4,0xB9,0x6C,0xAF,0xBE,0xED,0x20,0x56 } }; // 7699B465-1DCF-5791-B4B9-6CAFBEED2056
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor>{ 0xB4BAF068,0x8F49,0x446C,{ 0x8D,0xB5,0x8C,0x0F,0xFE,0x85,0xCC,0x9E } }; // B4BAF068-8F49-446C-8DB5-8C0FFE85CC9E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics>{ 0xF9F63BA2,0xCEBA,0x4755,{ 0x8A,0x7E,0x14,0xC0,0xFF,0xEC,0xD2,0x39 } }; // F9F63BA2-CEBA-4755-8A7E-14C0FFECD239
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationCompletedEventArgs>{ 0xB34AB22B,0xD19B,0x46FF,{ 0x9F,0x38,0xDE,0xC7,0x75,0x4B,0xB9,0xE7 } }; // B34AB22B-D19B-46FF-9F38-DEC7754BB9E7
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationCompletedEventArgs2>{ 0xF0C0DCE7,0x30A9,0x5B96,{ 0x88,0x6F,0x65,0x60,0xA8,0x5E,0x47,0x57 } }; // F0C0DCE7-30A9-5B96-886F-6560A85E4757
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs>{ 0xDD37A898,0x26BF,0x467A,{ 0x9C,0xE5,0xCC,0xF3,0xFB,0x11,0x37,0x1E } }; // DD37A898-26BF-467A-9CE5-CCF3FB11371E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2>{ 0xC25409B8,0xF9FA,0x5A45,{ 0xBD,0x97,0xDC,0xBB,0xB2,0x20,0x18,0x60 } }; // C25409B8-F9FA-5A45-BD97-DCBBB2201860
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationStartedEventArgs>{ 0xDDEC873E,0xCFCE,0x4932,{ 0x8C,0x1D,0x3C,0x3D,0x01,0x1A,0x34,0xC0 } }; // DDEC873E-CFCE-4932-8C1D-3C3D011A34C0
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationStartedEventArgs2>{ 0x2DA3DB4E,0xE583,0x5055,{ 0xAF,0xAA,0x16,0xFD,0x98,0x65,0x31,0xA6 } }; // 2DA3DB4E-E583-5055-AFAA-16FD986531A6
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs>{ 0xCB354CE5,0xABB8,0x4F9F,{ 0xB3,0xCE,0x81,0x81,0xAA,0x61,0xAD,0x82 } }; // CB354CE5-ABB8-4F9F-B3CE-8181AA61AD82
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2>{ 0xF3DFB96A,0x3306,0x5903,{ 0xA1,0xC5,0xFF,0x97,0x57,0xA8,0x68,0x9E } }; // F3DFB96A-3306-5903-A1C5-FF9757A8689E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IMouseWheelParameters>{ 0xEAD0CA44,0x9DED,0x4037,{ 0x81,0x49,0x5E,0x4C,0xC2,0x56,0x44,0x68 } }; // EAD0CA44-9DED-4037-8149-5E4CC2564468
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IPointerPoint>{ 0xE995317D,0x7296,0x42D9,{ 0x82,0x33,0xC5,0xBE,0x73,0xB7,0x4A,0x4A } }; // E995317D-7296-42D9-8233-C5BE73B74A4A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IPointerPointProperties>{ 0xC79D8A4B,0xC163,0x4EE7,{ 0x80,0x3F,0x67,0xCE,0x79,0xF9,0x97,0x2D } }; // C79D8A4B-C163-4EE7-803F-67CE79F9972D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IPointerPointProperties2>{ 0x22C3433A,0xC83B,0x41C0,{ 0xA2,0x96,0x5E,0x23,0x2D,0x64,0xD6,0xAF } }; // 22C3433A-C83B-41C0-A296-5E232D64D6AF
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IPointerPointStatics>{ 0xA506638D,0x2A1A,0x413E,{ 0xBC,0x75,0x9F,0x38,0x38,0x1C,0xC0,0x69 } }; // A506638D-2A1A-413E-BC75-9F38381CC069
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IPointerPointTransform>{ 0x4D5FE14F,0xB87C,0x4028,{ 0xBC,0x9C,0x59,0xE9,0x94,0x7F,0xB0,0x56 } }; // 4D5FE14F-B87C-4028-BC9C-59E9947FB056
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IPointerVisualizationSettings>{ 0x4D1E6461,0x84F7,0x499D,{ 0xBD,0x91,0x2A,0x36,0xE2,0xB7,0xAA,0xA2 } }; // 4D1E6461-84F7-499D-BD91-2A36E2B7AAA2
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics>{ 0x68870EDB,0x165B,0x4214,{ 0xB4,0xF3,0x58,0x4E,0xCA,0x8C,0x8A,0x69 } }; // 68870EDB-165B-4214-B4F3-584ECA8C8A69
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialController>{ 0x3055D1C8,0xDF51,0x43D4,{ 0xB2,0x3B,0x0E,0x10,0x37,0x46,0x7A,0x09 } }; // 3055D1C8-DF51-43D4-B23B-0E1037467A09
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialController2>{ 0x3D577EFF,0x4CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EFF-4CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs>{ 0x206AA438,0xE651,0x11E5,{ 0xBF,0x62,0x2C,0x27,0xD7,0x40,0x4E,0x85 } }; // 206AA438-E651-11E5-BF62-2C27D7404E85
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2>{ 0x3D577EF3,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF3-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs>{ 0x3D577EEE,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EEE-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs>{ 0x3D577EED,0x4CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EED-4CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs>{ 0x3D577EEF,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EEF-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerConfiguration>{ 0xA6B79ECB,0x6A52,0x4430,{ 0x91,0x0C,0x56,0x37,0x0A,0x9D,0x6B,0x42 } }; // A6B79ECB-6A52-4430-910C-56370A9D6B42
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerConfiguration2>{ 0x3D577EF7,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF7-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics>{ 0x79B6B0E5,0x069A,0x4486,{ 0xA9,0x9D,0x8D,0xB7,0x72,0xB9,0x64,0x2F } }; // 79B6B0E5-069A-4486-A99D-8DB772B9642F
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2>{ 0x53E08B17,0xE205,0x48D3,{ 0x9C,0xAF,0x80,0xFF,0x47,0xC4,0xD7,0xC7 } }; // 53E08B17-E205-48D3-9CAF-80FF47C4D7C7
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs>{ 0x206AA439,0xE651,0x11E5,{ 0xBF,0x62,0x2C,0x27,0xD7,0x40,0x4E,0x85 } }; // 206AA439-E651-11E5-BF62-2C27D7404E85
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2>{ 0x3D577EF4,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF4-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerMenu>{ 0x8506B35D,0xF640,0x4412,{ 0xAB,0xA0,0xBA,0xD0,0x77,0xE5,0xEA,0x8A } }; // 8506B35D-F640-4412-ABA0-BAD077E5EA8A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerMenuItem>{ 0xC80FC98D,0xAD0B,0x4C9C,{ 0x8F,0x2F,0x13,0x6A,0x23,0x73,0xA6,0xBA } }; // C80FC98D-AD0B-4C9C-8F2F-136A2373A6BA
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics>{ 0x249E0887,0xD842,0x4524,{ 0x9D,0xF8,0xE0,0xD6,0x47,0xED,0xC8,0x87 } }; // 249E0887-D842-4524-9DF8-E0D647EDC887
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2>{ 0x0CBB70BE,0x7E3E,0x48BD,{ 0xBE,0x04,0x2C,0x7F,0xCA,0xA9,0xC1,0xFF } }; // 0CBB70BE-7E3E-48BD-BE04-2C7FCAA9C1FF
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs>{ 0x206AA435,0xE651,0x11E5,{ 0xBF,0x62,0x2C,0x27,0xD7,0x40,0x4E,0x85 } }; // 206AA435-E651-11E5-BF62-2C27D7404E85
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2>{ 0x3D577EEC,0x4CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EEC-4CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerScreenContact>{ 0x206AA434,0xE651,0x11E5,{ 0xBF,0x62,0x2C,0x27,0xD7,0x40,0x4E,0x85 } }; // 206AA434-E651-11E5-BF62-2C27D7404E85
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs>{ 0x206AA437,0xE651,0x11E5,{ 0xBF,0x62,0x2C,0x27,0xD7,0x40,0x4E,0x85 } }; // 206AA437-E651-11E5-BF62-2C27D7404E85
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2>{ 0x3D577EF1,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF1-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs>{ 0x3D577EF2,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF2-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs>{ 0x206AA436,0xE651,0x11E5,{ 0xBF,0x62,0x2C,0x27,0xD7,0x40,0x4E,0x85 } }; // 206AA436-E651-11E5-BF62-2C27D7404E85
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2>{ 0x3D577EF0,0x3CEE,0x11E6,{ 0xB5,0x35,0x00,0x1B,0xDC,0x06,0xAB,0x3B } }; // 3D577EF0-3CEE-11E6-B535-001BDC06AB3B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRadialControllerStatics>{ 0xFADED0B7,0xB84C,0x4894,{ 0x87,0xAA,0x8F,0x25,0xAA,0x5F,0x28,0x8B } }; // FADED0B7-B84C-4894-87AA-8F25AA5F288B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRightTappedEventArgs>{ 0x4CBF40BD,0xAF7A,0x4A36,{ 0x94,0x76,0xB1,0xDC,0xE1,0x41,0x70,0x9A } }; // 4CBF40BD-AF7A-4A36-9476-B1DCE141709A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::IRightTappedEventArgs2>{ 0x61C7B7BB,0x9F57,0x5857,{ 0xA3,0x3C,0xC5,0x8C,0x3D,0xFA,0x95,0x9E } }; // 61C7B7BB-9F57-5857-A33C-C58C3DFA959E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ISystemButtonEventController>{ 0x59B893A9,0x73BC,0x52B5,{ 0xBA,0x41,0x82,0x51,0x1B,0x2C,0xB4,0x6C } }; // 59B893A9-73BC-52B5-BA41-82511B2CB46C
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ISystemButtonEventControllerStatics>{ 0x632FB07B,0x20BD,0x5E15,{ 0xAF,0x4A,0x00,0xDB,0xF2,0x06,0x4F,0xFA } }; // 632FB07B-20BD-5E15-AF4A-00DBF2064FFA
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs>{ 0x4833896F,0x80D1,0x5DD6,{ 0x92,0xA7,0x62,0xA5,0x08,0xFF,0xEF,0x5A } }; // 4833896F-80D1-5DD6-92A7-62A508FFEF5A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs>{ 0xCD040608,0xFCF9,0x585C,{ 0xBE,0xAB,0xF1,0xD2,0xEA,0xF3,0x64,0xAB } }; // CD040608-FCF9-585C-BEAB-F1D2EAF364AB
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs>{ 0xB212B94E,0x7A6F,0x58AE,{ 0xB3,0x04,0xBA,0xE6,0x1D,0x03,0x71,0xB9 } }; // B212B94E-7A6F-58AE-B304-BAE61D0371B9
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ITappedEventArgs>{ 0xCFA126E4,0x253A,0x4C3C,{ 0x95,0x3B,0x39,0x5C,0x37,0xAE,0xD3,0x09 } }; // CFA126E4-253A-4C3C-953B-395C37AED309
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Input::ITappedEventArgs2>{ 0x294388F2,0x177E,0x51D5,{ 0xBE,0x56,0xEE,0x08,0x66,0xFA,0x96,0x8C } }; // 294388F2-177E-51D5-BE56-EE0866FA968C
    template <> struct default_interface<winrt::Windows::UI::Input::AttachableInputObject>{ using type = winrt::Windows::UI::Input::IAttachableInputObject; };
    template <> struct default_interface<winrt::Windows::UI::Input::CrossSlidingEventArgs>{ using type = winrt::Windows::UI::Input::ICrossSlidingEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::DraggingEventArgs>{ using type = winrt::Windows::UI::Input::IDraggingEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::EdgeGesture>{ using type = winrt::Windows::UI::Input::IEdgeGesture; };
    template <> struct default_interface<winrt::Windows::UI::Input::EdgeGestureEventArgs>{ using type = winrt::Windows::UI::Input::IEdgeGestureEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::GestureRecognizer>{ using type = winrt::Windows::UI::Input::IGestureRecognizer; };
    template <> struct default_interface<winrt::Windows::UI::Input::HoldingEventArgs>{ using type = winrt::Windows::UI::Input::IHoldingEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::InputActivationListener>{ using type = winrt::Windows::UI::Input::IInputActivationListener; };
    template <> struct default_interface<winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs>{ using type = winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor>{ using type = winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor; };
    template <> struct default_interface<winrt::Windows::UI::Input::ManipulationCompletedEventArgs>{ using type = winrt::Windows::UI::Input::IManipulationCompletedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs>{ using type = winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::ManipulationStartedEventArgs>{ using type = winrt::Windows::UI::Input::IManipulationStartedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::ManipulationUpdatedEventArgs>{ using type = winrt::Windows::UI::Input::IManipulationUpdatedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::MouseWheelParameters>{ using type = winrt::Windows::UI::Input::IMouseWheelParameters; };
    template <> struct default_interface<winrt::Windows::UI::Input::PointerPoint>{ using type = winrt::Windows::UI::Input::IPointerPoint; };
    template <> struct default_interface<winrt::Windows::UI::Input::PointerPointProperties>{ using type = winrt::Windows::UI::Input::IPointerPointProperties; };
    template <> struct default_interface<winrt::Windows::UI::Input::PointerVisualizationSettings>{ using type = winrt::Windows::UI::Input::IPointerVisualizationSettings; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialController>{ using type = winrt::Windows::UI::Input::IRadialController; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerConfiguration>{ using type = winrt::Windows::UI::Input::IRadialControllerConfiguration; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerMenu>{ using type = winrt::Windows::UI::Input::IRadialControllerMenu; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerMenuItem>{ using type = winrt::Windows::UI::Input::IRadialControllerMenuItem; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerScreenContact>{ using type = winrt::Windows::UI::Input::IRadialControllerScreenContact; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerScreenContactEndedEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs>{ using type = winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::RightTappedEventArgs>{ using type = winrt::Windows::UI::Input::IRightTappedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::SystemButtonEventController>{ using type = winrt::Windows::UI::Input::ISystemButtonEventController; };
    template <> struct default_interface<winrt::Windows::UI::Input::SystemFunctionButtonEventArgs>{ using type = winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs>{ using type = winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs>{ using type = winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Input::TappedEventArgs>{ using type = winrt::Windows::UI::Input::ITappedEventArgs; };
    template <> struct abi<winrt::Windows::UI::Input::IAttachableInputObject>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IAttachableInputObjectFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ICrossSlidingEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_CrossSlidingState(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ICrossSlidingEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IDraggingEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_DraggingState(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IDraggingEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IEdgeGesture>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Starting(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Starting(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Completed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Completed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Canceled(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Canceled(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IEdgeGestureEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Kind(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IEdgeGestureStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IGestureRecognizer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_GestureSettings(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_GestureSettings(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsInertial(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsActive(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ShowGestureFeedback(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ShowGestureFeedback(bool) noexcept = 0;
            virtual int32_t __stdcall get_PivotCenter(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall put_PivotCenter(winrt::Windows::Foundation::Point) noexcept = 0;
            virtual int32_t __stdcall get_PivotRadius(float*) noexcept = 0;
            virtual int32_t __stdcall put_PivotRadius(float) noexcept = 0;
            virtual int32_t __stdcall get_InertiaTranslationDeceleration(float*) noexcept = 0;
            virtual int32_t __stdcall put_InertiaTranslationDeceleration(float) noexcept = 0;
            virtual int32_t __stdcall get_InertiaRotationDeceleration(float*) noexcept = 0;
            virtual int32_t __stdcall put_InertiaRotationDeceleration(float) noexcept = 0;
            virtual int32_t __stdcall get_InertiaExpansionDeceleration(float*) noexcept = 0;
            virtual int32_t __stdcall put_InertiaExpansionDeceleration(float) noexcept = 0;
            virtual int32_t __stdcall get_InertiaTranslationDisplacement(float*) noexcept = 0;
            virtual int32_t __stdcall put_InertiaTranslationDisplacement(float) noexcept = 0;
            virtual int32_t __stdcall get_InertiaRotationAngle(float*) noexcept = 0;
            virtual int32_t __stdcall put_InertiaRotationAngle(float) noexcept = 0;
            virtual int32_t __stdcall get_InertiaExpansion(float*) noexcept = 0;
            virtual int32_t __stdcall put_InertiaExpansion(float) noexcept = 0;
            virtual int32_t __stdcall get_ManipulationExact(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ManipulationExact(bool) noexcept = 0;
            virtual int32_t __stdcall get_CrossSlideThresholds(struct struct_Windows_UI_Input_CrossSlideThresholds*) noexcept = 0;
            virtual int32_t __stdcall put_CrossSlideThresholds(struct struct_Windows_UI_Input_CrossSlideThresholds) noexcept = 0;
            virtual int32_t __stdcall get_CrossSlideHorizontally(bool*) noexcept = 0;
            virtual int32_t __stdcall put_CrossSlideHorizontally(bool) noexcept = 0;
            virtual int32_t __stdcall get_CrossSlideExact(bool*) noexcept = 0;
            virtual int32_t __stdcall put_CrossSlideExact(bool) noexcept = 0;
            virtual int32_t __stdcall get_AutoProcessInertia(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AutoProcessInertia(bool) noexcept = 0;
            virtual int32_t __stdcall get_MouseWheelParameters(void**) noexcept = 0;
            virtual int32_t __stdcall CanBeDoubleTap(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall ProcessDownEvent(void*) noexcept = 0;
            virtual int32_t __stdcall ProcessMoveEvents(void*) noexcept = 0;
            virtual int32_t __stdcall ProcessUpEvent(void*) noexcept = 0;
            virtual int32_t __stdcall ProcessMouseWheelEvent(void*, bool, bool) noexcept = 0;
            virtual int32_t __stdcall ProcessInertia() noexcept = 0;
            virtual int32_t __stdcall CompleteGesture() noexcept = 0;
            virtual int32_t __stdcall add_Tapped(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Tapped(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_RightTapped(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RightTapped(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Holding(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Holding(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Dragging(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Dragging(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ManipulationStarted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ManipulationStarted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ManipulationUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ManipulationUpdated(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ManipulationInertiaStarting(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ManipulationInertiaStarting(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ManipulationCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ManipulationCompleted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_CrossSliding(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_CrossSliding(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IGestureRecognizer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TapMinContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TapMinContactCount(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_TapMaxContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TapMaxContactCount(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_HoldMinContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_HoldMinContactCount(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_HoldMaxContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_HoldMaxContactCount(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_HoldRadius(float*) noexcept = 0;
            virtual int32_t __stdcall put_HoldRadius(float) noexcept = 0;
            virtual int32_t __stdcall get_HoldStartDelay(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_HoldStartDelay(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_TranslationMinContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TranslationMinContactCount(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_TranslationMaxContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TranslationMaxContactCount(uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IHoldingEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_HoldingState(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IHoldingEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CurrentContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IInputActivationListener>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_InputActivationChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_InputActivationChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsInterceptionEnabledWhenInForeground(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsInterceptionEnabledWhenInForeground(bool) noexcept = 0;
            virtual int32_t __stdcall add_KeyDown(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_KeyDown(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_KeyUp(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_KeyUp(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta*) noexcept = 0;
            virtual int32_t __stdcall get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationCompletedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CurrentContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_Delta(struct struct_Windows_UI_Input_ManipulationDelta*) noexcept = 0;
            virtual int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta*) noexcept = 0;
            virtual int32_t __stdcall get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationStartedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationStartedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_Delta(struct struct_Windows_UI_Input_ManipulationDelta*) noexcept = 0;
            virtual int32_t __stdcall get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta*) noexcept = 0;
            virtual int32_t __stdcall get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CurrentContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IMouseWheelParameters>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CharTranslation(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall put_CharTranslation(winrt::Windows::Foundation::Point) noexcept = 0;
            virtual int32_t __stdcall get_DeltaScale(float*) noexcept = 0;
            virtual int32_t __stdcall put_DeltaScale(float) noexcept = 0;
            virtual int32_t __stdcall get_DeltaRotationAngle(float*) noexcept = 0;
            virtual int32_t __stdcall put_DeltaRotationAngle(float) noexcept = 0;
            virtual int32_t __stdcall get_PageTranslation(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall put_PageTranslation(winrt::Windows::Foundation::Point) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IPointerPoint>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDevice(void**) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_RawPosition(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_PointerId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_FrameId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Timestamp(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsInContact(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IPointerPointProperties>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Pressure(float*) noexcept = 0;
            virtual int32_t __stdcall get_IsInverted(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsEraser(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Orientation(float*) noexcept = 0;
            virtual int32_t __stdcall get_XTilt(float*) noexcept = 0;
            virtual int32_t __stdcall get_YTilt(float*) noexcept = 0;
            virtual int32_t __stdcall get_Twist(float*) noexcept = 0;
            virtual int32_t __stdcall get_ContactRect(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall get_ContactRectRaw(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall get_TouchConfidence(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsLeftButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsRightButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsMiddleButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_MouseWheelDelta(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsHorizontalMouseWheel(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsPrimary(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsInRange(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCanceled(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsBarrelButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsXButton1Pressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsXButton2Pressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_PointerUpdateKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall HasUsage(uint32_t, uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall GetUsageValue(uint32_t, uint32_t, int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IPointerPointProperties2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ZDistance(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IPointerPointStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCurrentPoint(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetIntermediatePoints(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetCurrentPointTransformed(uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetIntermediatePointsTransformed(uint32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IPointerPointTransform>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Inverse(void**) noexcept = 0;
            virtual int32_t __stdcall TryTransform(winrt::Windows::Foundation::Point, winrt::Windows::Foundation::Point*, bool*) noexcept = 0;
            virtual int32_t __stdcall TransformBounds(winrt::Windows::Foundation::Rect, winrt::Windows::Foundation::Rect*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IPointerVisualizationSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_IsContactFeedbackEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsContactFeedbackEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsBarrelButtonFeedbackEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsBarrelButtonFeedbackEnabled(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialController>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Menu(void**) noexcept = 0;
            virtual int32_t __stdcall get_RotationResolutionInDegrees(double*) noexcept = 0;
            virtual int32_t __stdcall put_RotationResolutionInDegrees(double) noexcept = 0;
            virtual int32_t __stdcall get_UseAutomaticHapticFeedback(bool*) noexcept = 0;
            virtual int32_t __stdcall put_UseAutomaticHapticFeedback(bool) noexcept = 0;
            virtual int32_t __stdcall add_ScreenContactStarted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ScreenContactStarted(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ScreenContactEnded(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ScreenContactEnded(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ScreenContactContinued(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ScreenContactContinued(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ControlLost(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ControlLost(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_RotationChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RotationChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ButtonClicked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ButtonClicked(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ControlAcquired(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ControlAcquired(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialController2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_ButtonPressed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ButtonPressed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ButtonHolding(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ButtonHolding(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ButtonReleased(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ButtonReleased(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerConfiguration>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetDefaultMenuItems(void*) noexcept = 0;
            virtual int32_t __stdcall ResetToDefaultMenuItems() noexcept = 0;
            virtual int32_t __stdcall TrySelectDefaultMenuItem(int32_t, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerConfiguration2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ActiveControllerWhenMenuIsSuppressed(void*) noexcept = 0;
            virtual int32_t __stdcall get_ActiveControllerWhenMenuIsSuppressed(void**) noexcept = 0;
            virtual int32_t __stdcall put_IsMenuSuppressed(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsMenuSuppressed(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_AppController(void*) noexcept = 0;
            virtual int32_t __stdcall get_AppController(void**) noexcept = 0;
            virtual int32_t __stdcall put_IsAppControllerEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsAppControllerEnabled(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerMenu>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Items(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall GetSelectedMenuItem(void**) noexcept = 0;
            virtual int32_t __stdcall SelectMenuItem(void*) noexcept = 0;
            virtual int32_t __stdcall TrySelectPreviouslySelectedMenuItem(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerMenuItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayText(void**) noexcept = 0;
            virtual int32_t __stdcall get_Tag(void**) noexcept = 0;
            virtual int32_t __stdcall put_Tag(void*) noexcept = 0;
            virtual int32_t __stdcall add_Invoked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Invoked(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFromIcon(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFromKnownIcon(void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFromFontGlyph(void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFromFontGlyphWithUri(void*, void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RotationDeltaInDegrees(double*) noexcept = 0;
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerScreenContact>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Bounds(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contact(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsButtonPressed(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SimpleHapticsController(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRadialControllerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall CreateForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRightTappedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::IRightTappedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ISystemButtonEventController>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_SystemFunctionButtonPressed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SystemFunctionButtonPressed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SystemFunctionButtonReleased(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SystemFunctionButtonReleased(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SystemFunctionLockChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SystemFunctionLockChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SystemFunctionLockIndicatorChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SystemFunctionLockIndicatorChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ISystemButtonEventControllerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateForDispatcherQueue(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_Handled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Handled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsLocked(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Handled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Handled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsIndicatorOn(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Handled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Handled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ITappedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PointerDeviceType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall get_TapCount(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Input::ITappedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContactCount(uint32_t*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_Input_IAttachableInputObject
    {
    };
    template <> struct consume<winrt::Windows::UI::Input::IAttachableInputObject>
    {
        template <typename D> using type = consume_Windows_UI_Input_IAttachableInputObject<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IAttachableInputObjectFactory
    {
    };
    template <> struct consume<winrt::Windows::UI::Input::IAttachableInputObjectFactory>
    {
        template <typename D> using type = consume_Windows_UI_Input_IAttachableInputObjectFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ICrossSlidingEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::CrossSlidingState) CrossSlidingState() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ICrossSlidingEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_ICrossSlidingEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ICrossSlidingEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ICrossSlidingEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_ICrossSlidingEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IDraggingEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::DraggingState) DraggingState() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IDraggingEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IDraggingEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IDraggingEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IDraggingEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IDraggingEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IEdgeGesture
    {
        WINRT_IMPL_AUTO(winrt::event_token) Starting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const;
        using Starting_revoker = impl::event_revoker<winrt::Windows::UI::Input::IEdgeGesture, &impl::abi_t<winrt::Windows::UI::Input::IEdgeGesture>::remove_Starting>;
        [[nodiscard]] Starting_revoker Starting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Starting(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Completed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const;
        using Completed_revoker = impl::event_revoker<winrt::Windows::UI::Input::IEdgeGesture, &impl::abi_t<winrt::Windows::UI::Input::IEdgeGesture>::remove_Completed>;
        [[nodiscard]] Completed_revoker Completed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Completed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Canceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const;
        using Canceled_revoker = impl::event_revoker<winrt::Windows::UI::Input::IEdgeGesture, &impl::abi_t<winrt::Windows::UI::Input::IEdgeGesture>::remove_Canceled>;
        [[nodiscard]] Canceled_revoker Canceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::EdgeGesture, winrt::Windows::UI::Input::EdgeGestureEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Canceled(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::IEdgeGesture>
    {
        template <typename D> using type = consume_Windows_UI_Input_IEdgeGesture<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IEdgeGestureEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::EdgeGestureKind) Kind() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IEdgeGestureEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IEdgeGestureEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IEdgeGestureStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::EdgeGesture) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IEdgeGestureStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_IEdgeGestureStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IGestureRecognizer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::GestureSettings) GestureSettings() const;
        WINRT_IMPL_AUTO(void) GestureSettings(winrt::Windows::UI::Input::GestureSettings const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInertial() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsActive() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ShowGestureFeedback() const;
        WINRT_IMPL_AUTO(void) ShowGestureFeedback(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) PivotCenter() const;
        WINRT_IMPL_AUTO(void) PivotCenter(winrt::Windows::Foundation::Point const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) PivotRadius() const;
        WINRT_IMPL_AUTO(void) PivotRadius(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) InertiaTranslationDeceleration() const;
        WINRT_IMPL_AUTO(void) InertiaTranslationDeceleration(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) InertiaRotationDeceleration() const;
        WINRT_IMPL_AUTO(void) InertiaRotationDeceleration(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) InertiaExpansionDeceleration() const;
        WINRT_IMPL_AUTO(void) InertiaExpansionDeceleration(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) InertiaTranslationDisplacement() const;
        WINRT_IMPL_AUTO(void) InertiaTranslationDisplacement(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) InertiaRotationAngle() const;
        WINRT_IMPL_AUTO(void) InertiaRotationAngle(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) InertiaExpansion() const;
        WINRT_IMPL_AUTO(void) InertiaExpansion(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ManipulationExact() const;
        WINRT_IMPL_AUTO(void) ManipulationExact(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::CrossSlideThresholds) CrossSlideThresholds() const;
        WINRT_IMPL_AUTO(void) CrossSlideThresholds(winrt::Windows::UI::Input::CrossSlideThresholds const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CrossSlideHorizontally() const;
        WINRT_IMPL_AUTO(void) CrossSlideHorizontally(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CrossSlideExact() const;
        WINRT_IMPL_AUTO(void) CrossSlideExact(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AutoProcessInertia() const;
        WINRT_IMPL_AUTO(void) AutoProcessInertia(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::MouseWheelParameters) MouseWheelParameters() const;
        WINRT_IMPL_AUTO(bool) CanBeDoubleTap(winrt::Windows::UI::Input::PointerPoint const& value) const;
        WINRT_IMPL_AUTO(void) ProcessDownEvent(winrt::Windows::UI::Input::PointerPoint const& value) const;
        WINRT_IMPL_AUTO(void) ProcessMoveEvents(param::vector<winrt::Windows::UI::Input::PointerPoint> const& value) const;
        WINRT_IMPL_AUTO(void) ProcessUpEvent(winrt::Windows::UI::Input::PointerPoint const& value) const;
        WINRT_IMPL_AUTO(void) ProcessMouseWheelEvent(winrt::Windows::UI::Input::PointerPoint const& value, bool isShiftKeyDown, bool isControlKeyDown) const;
        WINRT_IMPL_AUTO(void) ProcessInertia() const;
        WINRT_IMPL_AUTO(void) CompleteGesture() const;
        WINRT_IMPL_AUTO(winrt::event_token) Tapped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::TappedEventArgs> const& handler) const;
        using Tapped_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_Tapped>;
        [[nodiscard]] Tapped_revoker Tapped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::TappedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Tapped(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) RightTapped(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::RightTappedEventArgs> const& handler) const;
        using RightTapped_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_RightTapped>;
        [[nodiscard]] RightTapped_revoker RightTapped(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::RightTappedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) RightTapped(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Holding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::HoldingEventArgs> const& handler) const;
        using Holding_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_Holding>;
        [[nodiscard]] Holding_revoker Holding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::HoldingEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Holding(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Dragging(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::DraggingEventArgs> const& handler) const;
        using Dragging_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_Dragging>;
        [[nodiscard]] Dragging_revoker Dragging(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::DraggingEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Dragging(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ManipulationStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationStartedEventArgs> const& handler) const;
        using ManipulationStarted_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_ManipulationStarted>;
        [[nodiscard]] ManipulationStarted_revoker ManipulationStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationStartedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ManipulationStarted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ManipulationUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> const& handler) const;
        using ManipulationUpdated_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_ManipulationUpdated>;
        [[nodiscard]] ManipulationUpdated_revoker ManipulationUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ManipulationUpdated(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ManipulationInertiaStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> const& handler) const;
        using ManipulationInertiaStarting_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_ManipulationInertiaStarting>;
        [[nodiscard]] ManipulationInertiaStarting_revoker ManipulationInertiaStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ManipulationInertiaStarting(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ManipulationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationCompletedEventArgs> const& handler) const;
        using ManipulationCompleted_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_ManipulationCompleted>;
        [[nodiscard]] ManipulationCompleted_revoker ManipulationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::ManipulationCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ManipulationCompleted(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) CrossSliding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::CrossSlidingEventArgs> const& handler) const;
        using CrossSliding_revoker = impl::event_revoker<winrt::Windows::UI::Input::IGestureRecognizer, &impl::abi_t<winrt::Windows::UI::Input::IGestureRecognizer>::remove_CrossSliding>;
        [[nodiscard]] CrossSliding_revoker CrossSliding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::GestureRecognizer, winrt::Windows::UI::Input::CrossSlidingEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) CrossSliding(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::IGestureRecognizer>
    {
        template <typename D> using type = consume_Windows_UI_Input_IGestureRecognizer<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IGestureRecognizer2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TapMinContactCount() const;
        WINRT_IMPL_AUTO(void) TapMinContactCount(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TapMaxContactCount() const;
        WINRT_IMPL_AUTO(void) TapMaxContactCount(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) HoldMinContactCount() const;
        WINRT_IMPL_AUTO(void) HoldMinContactCount(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) HoldMaxContactCount() const;
        WINRT_IMPL_AUTO(void) HoldMaxContactCount(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) HoldRadius() const;
        WINRT_IMPL_AUTO(void) HoldRadius(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) HoldStartDelay() const;
        WINRT_IMPL_AUTO(void) HoldStartDelay(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TranslationMinContactCount() const;
        WINRT_IMPL_AUTO(void) TranslationMinContactCount(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TranslationMaxContactCount() const;
        WINRT_IMPL_AUTO(void) TranslationMaxContactCount(uint32_t value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IGestureRecognizer2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IGestureRecognizer2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IHoldingEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::HoldingState) HoldingState() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IHoldingEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IHoldingEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IHoldingEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CurrentContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IHoldingEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IHoldingEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IInputActivationListener
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::InputActivationState) State() const;
        WINRT_IMPL_AUTO(winrt::event_token) InputActivationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::InputActivationListener, winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const& handler) const;
        using InputActivationChanged_revoker = impl::event_revoker<winrt::Windows::UI::Input::IInputActivationListener, &impl::abi_t<winrt::Windows::UI::Input::IInputActivationListener>::remove_InputActivationChanged>;
        [[nodiscard]] InputActivationChanged_revoker InputActivationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::InputActivationListener, winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) InputActivationChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::IInputActivationListener>
    {
        template <typename D> using type = consume_Windows_UI_Input_IInputActivationListener<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IInputActivationListenerActivationChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::InputActivationState) State() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IInputActivationListenerActivationChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IKeyboardDeliveryInterceptor
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInterceptionEnabledWhenInForeground() const;
        WINRT_IMPL_AUTO(void) IsInterceptionEnabledWhenInForeground(bool value) const;
        WINRT_IMPL_AUTO(winrt::event_token) KeyDown(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const;
        using KeyDown_revoker = impl::event_revoker<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor, &impl::abi_t<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor>::remove_KeyDown>;
        [[nodiscard]] KeyDown_revoker KeyDown(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) KeyDown(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) KeyUp(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const;
        using KeyUp_revoker = impl::event_revoker<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor, &impl::abi_t<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor>::remove_KeyUp>;
        [[nodiscard]] KeyUp_revoker KeyUp(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) KeyUp(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor>
    {
        template <typename D> using type = consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IKeyboardDeliveryInterceptorStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::KeyboardDeliveryInterceptor) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_IKeyboardDeliveryInterceptorStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) Cumulative() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) Velocities() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationCompletedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CurrentContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationCompletedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationCompletedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) Delta() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) Cumulative() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) Velocities() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationStartedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) Cumulative() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationStartedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationStartedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationStartedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationStartedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationStartedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationUpdatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) Delta() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationDelta) Cumulative() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::ManipulationVelocities) Velocities() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IManipulationUpdatedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CurrentContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IManipulationUpdatedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IMouseWheelParameters
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) CharTranslation() const;
        WINRT_IMPL_AUTO(void) CharTranslation(winrt::Windows::Foundation::Point const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) DeltaScale() const;
        WINRT_IMPL_AUTO(void) DeltaScale(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) DeltaRotationAngle() const;
        WINRT_IMPL_AUTO(void) DeltaRotationAngle(float value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) PageTranslation() const;
        WINRT_IMPL_AUTO(void) PageTranslation(winrt::Windows::Foundation::Point const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IMouseWheelParameters>
    {
        template <typename D> using type = consume_Windows_UI_Input_IMouseWheelParameters<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IPointerPoint
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDevice) PointerDevice() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) RawPosition() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) PointerId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) FrameId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInContact() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPointProperties) Properties() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IPointerPoint>
    {
        template <typename D> using type = consume_Windows_UI_Input_IPointerPoint<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IPointerPointProperties
    {
        [[nodiscard]] WINRT_IMPL_AUTO(float) Pressure() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInverted() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEraser() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) Orientation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) XTilt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) YTilt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(float) Twist() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) ContactRect() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) ContactRectRaw() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) TouchConfidence() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLeftButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsRightButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsMiddleButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) MouseWheelDelta() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsHorizontalMouseWheel() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPrimary() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInRange() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCanceled() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBarrelButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsXButton1Pressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsXButton2Pressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerUpdateKind) PointerUpdateKind() const;
        WINRT_IMPL_AUTO(bool) HasUsage(uint32_t usagePage, uint32_t usageId) const;
        WINRT_IMPL_AUTO(int32_t) GetUsageValue(uint32_t usagePage, uint32_t usageId) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IPointerPointProperties>
    {
        template <typename D> using type = consume_Windows_UI_Input_IPointerPointProperties<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IPointerPointProperties2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) ZDistance() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IPointerPointProperties2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IPointerPointProperties2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IPointerPointStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPoint) GetCurrentPoint(uint32_t pointerId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>) GetIntermediatePoints(uint32_t pointerId) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPoint) GetCurrentPoint(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>) GetIntermediatePoints(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IPointerPointStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_IPointerPointStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IPointerPointTransform
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::IPointerPointTransform) Inverse() const;
        WINRT_IMPL_AUTO(bool) TryTransform(winrt::Windows::Foundation::Point const& inPoint, winrt::Windows::Foundation::Point& outPoint) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) TransformBounds(winrt::Windows::Foundation::Rect const& rect) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IPointerPointTransform>
    {
        template <typename D> using type = consume_Windows_UI_Input_IPointerPointTransform<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IPointerVisualizationSettings
    {
        WINRT_IMPL_AUTO(void) IsContactFeedbackEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsContactFeedbackEnabled() const;
        WINRT_IMPL_AUTO(void) IsBarrelButtonFeedbackEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBarrelButtonFeedbackEnabled() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IPointerVisualizationSettings>
    {
        template <typename D> using type = consume_Windows_UI_Input_IPointerVisualizationSettings<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IPointerVisualizationSettingsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerVisualizationSettings) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_IPointerVisualizationSettingsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialController
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenu) Menu() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) RotationResolutionInDegrees() const;
        WINRT_IMPL_AUTO(void) RotationResolutionInDegrees(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) UseAutomaticHapticFeedback() const;
        WINRT_IMPL_AUTO(void) UseAutomaticHapticFeedback(bool value) const;
        WINRT_IMPL_AUTO(winrt::event_token) ScreenContactStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const& handler) const;
        using ScreenContactStarted_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController, &impl::abi_t<winrt::Windows::UI::Input::IRadialController>::remove_ScreenContactStarted>;
        [[nodiscard]] ScreenContactStarted_revoker ScreenContactStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ScreenContactStarted(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ScreenContactEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ScreenContactEnded_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController, &impl::abi_t<winrt::Windows::UI::Input::IRadialController>::remove_ScreenContactEnded>;
        [[nodiscard]] ScreenContactEnded_revoker ScreenContactEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ScreenContactEnded(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ScreenContactContinued(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const& handler) const;
        using ScreenContactContinued_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController, &impl::abi_t<winrt::Windows::UI::Input::IRadialController>::remove_ScreenContactContinued>;
        [[nodiscard]] ScreenContactContinued_revoker ScreenContactContinued(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ScreenContactContinued(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ControlLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ControlLost_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController, &impl::abi_t<winrt::Windows::UI::Input::IRadialController>::remove_ControlLost>;
        [[nodiscard]] ControlLost_revoker ControlLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ControlLost(winrt::event_token const& cookie) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) RotationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> const& handler) const;
        using RotationChanged_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController, &impl::abi_t<winrt::Windows::UI::Input::IRadialController>::remove_RotationChanged>;
        [[nodiscard]] RotationChanged_revoker RotationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) RotationChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ButtonClicked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> const& handler) const;
        using ButtonClicked_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController, &impl::abi_t<winrt::Windows::UI::Input::IRadialController>::remove_ButtonClicked>;
        [[nodiscard]] ButtonClicked_revoker ButtonClicked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ButtonClicked(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ControlAcquired(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const& handler) const;
        using ControlAcquired_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController, &impl::abi_t<winrt::Windows::UI::Input::IRadialController>::remove_ControlAcquired>;
        [[nodiscard]] ControlAcquired_revoker ControlAcquired(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ControlAcquired(winrt::event_token const& cookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialController>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialController<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialController2
    {
        WINRT_IMPL_AUTO(winrt::event_token) ButtonPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> const& handler) const;
        using ButtonPressed_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController2, &impl::abi_t<winrt::Windows::UI::Input::IRadialController2>::remove_ButtonPressed>;
        [[nodiscard]] ButtonPressed_revoker ButtonPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ButtonPressed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ButtonHolding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const& handler) const;
        using ButtonHolding_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController2, &impl::abi_t<winrt::Windows::UI::Input::IRadialController2>::remove_ButtonHolding>;
        [[nodiscard]] ButtonHolding_revoker ButtonHolding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ButtonHolding(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ButtonReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const& handler) const;
        using ButtonReleased_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialController2, &impl::abi_t<winrt::Windows::UI::Input::IRadialController2>::remove_ButtonReleased>;
        [[nodiscard]] ButtonReleased_revoker ButtonReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialController, winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ButtonReleased(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialController2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialController2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerButtonHoldingEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerButtonHoldingEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerButtonPressedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerButtonPressedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerButtonReleasedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerButtonReleasedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerConfiguration
    {
        WINRT_IMPL_AUTO(void) SetDefaultMenuItems(param::iterable<winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind> const& buttons) const;
        WINRT_IMPL_AUTO(void) ResetToDefaultMenuItems() const;
        WINRT_IMPL_AUTO(bool) TrySelectDefaultMenuItem(winrt::Windows::UI::Input::RadialControllerSystemMenuItemKind const& type) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerConfiguration>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerConfiguration<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerConfiguration2
    {
        WINRT_IMPL_AUTO(void) ActiveControllerWhenMenuIsSuppressed(winrt::Windows::UI::Input::RadialController const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) ActiveControllerWhenMenuIsSuppressed() const;
        WINRT_IMPL_AUTO(void) IsMenuSuppressed(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsMenuSuppressed() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerConfiguration2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerConfiguration2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerConfigurationStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerConfiguration) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerConfigurationStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerConfigurationStatics2
    {
        WINRT_IMPL_AUTO(void) AppController(winrt::Windows::UI::Input::RadialController const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) AppController() const;
        WINRT_IMPL_AUTO(void) IsAppControllerEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAppControllerEnabled() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerMenu
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::RadialControllerMenuItem>) Items() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        WINRT_IMPL_AUTO(void) IsEnabled(bool value) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) GetSelectedMenuItem() const;
        WINRT_IMPL_AUTO(void) SelectMenuItem(winrt::Windows::UI::Input::RadialControllerMenuItem const& menuItem) const;
        WINRT_IMPL_AUTO(bool) TrySelectPreviouslySelectedMenuItem() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerMenu>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerMenu<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerMenuItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayText() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) Tag() const;
        WINRT_IMPL_AUTO(void) Tag(winrt::Windows::Foundation::IInspectable const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) Invoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialControllerMenuItem, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using Invoked_revoker = impl::event_revoker<winrt::Windows::UI::Input::IRadialControllerMenuItem, &impl::abi_t<winrt::Windows::UI::Input::IRadialControllerMenuItem>::remove_Invoked>;
        [[nodiscard]] Invoked_revoker Invoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::RadialControllerMenuItem, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) Invoked(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerMenuItem>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerMenuItem<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerMenuItemStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) CreateFromIcon(param::hstring const& displayText, winrt::Windows::Storage::Streams::RandomAccessStreamReference const& icon) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) CreateFromKnownIcon(param::hstring const& displayText, winrt::Windows::UI::Input::RadialControllerMenuKnownIcon const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerMenuItemStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerMenuItemStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerMenuItem) CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily, winrt::Windows::Foundation::Uri const& fontUri) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerMenuItemStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) RotationDeltaInDegrees() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerScreenContact
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) Bounds() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerScreenContact>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerScreenContact<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerScreenContactEndedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerScreenContactEndedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialControllerScreenContact) Contact() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsButtonPressed() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) SimpleHapticsController() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRadialControllerStatics
    {
        WINRT_IMPL_AUTO(bool) IsSupported() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) CreateForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRadialControllerStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRadialControllerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRightTappedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRightTappedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRightTappedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_IRightTappedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::IRightTappedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_IRightTappedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ISystemButtonEventController
    {
        WINRT_IMPL_AUTO(winrt::event_token) SystemFunctionButtonPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const;
        using SystemFunctionButtonPressed_revoker = impl::event_revoker<winrt::Windows::UI::Input::ISystemButtonEventController, &impl::abi_t<winrt::Windows::UI::Input::ISystemButtonEventController>::remove_SystemFunctionButtonPressed>;
        [[nodiscard]] SystemFunctionButtonPressed_revoker SystemFunctionButtonPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SystemFunctionButtonPressed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SystemFunctionButtonReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const;
        using SystemFunctionButtonReleased_revoker = impl::event_revoker<winrt::Windows::UI::Input::ISystemButtonEventController, &impl::abi_t<winrt::Windows::UI::Input::ISystemButtonEventController>::remove_SystemFunctionButtonReleased>;
        [[nodiscard]] SystemFunctionButtonReleased_revoker SystemFunctionButtonReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionButtonEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SystemFunctionButtonReleased(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SystemFunctionLockChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs> const& handler) const;
        using SystemFunctionLockChanged_revoker = impl::event_revoker<winrt::Windows::UI::Input::ISystemButtonEventController, &impl::abi_t<winrt::Windows::UI::Input::ISystemButtonEventController>::remove_SystemFunctionLockChanged>;
        [[nodiscard]] SystemFunctionLockChanged_revoker SystemFunctionLockChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SystemFunctionLockChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SystemFunctionLockIndicatorChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs> const& handler) const;
        using SystemFunctionLockIndicatorChanged_revoker = impl::event_revoker<winrt::Windows::UI::Input::ISystemButtonEventController, &impl::abi_t<winrt::Windows::UI::Input::ISystemButtonEventController>::remove_SystemFunctionLockIndicatorChanged>;
        [[nodiscard]] SystemFunctionLockIndicatorChanged_revoker SystemFunctionLockIndicatorChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Input::SystemButtonEventController, winrt::Windows::UI::Input::SystemFunctionLockIndicatorChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) SystemFunctionLockIndicatorChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Input::ISystemButtonEventController>
    {
        template <typename D> using type = consume_Windows_UI_Input_ISystemButtonEventController<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ISystemButtonEventControllerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Input::SystemButtonEventController) CreateForDispatcherQueue(winrt::Windows::System::DispatcherQueue const& queue) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ISystemButtonEventControllerStatics>
    {
        template <typename D> using type = consume_Windows_UI_Input_ISystemButtonEventControllerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ISystemFunctionButtonEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Handled() const;
        WINRT_IMPL_AUTO(void) Handled(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_ISystemFunctionButtonEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ISystemFunctionLockChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLocked() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Handled() const;
        WINRT_IMPL_AUTO(void) Handled(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_ISystemFunctionLockChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ISystemFunctionLockIndicatorChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsIndicatorOn() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Handled() const;
        WINRT_IMPL_AUTO(void) Handled(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_ISystemFunctionLockIndicatorChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ITappedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Input::PointerDeviceType) PointerDeviceType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TapCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ITappedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Input_ITappedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Input_ITappedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ContactCount() const;
    };
    template <> struct consume<winrt::Windows::UI::Input::ITappedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_Input_ITappedEventArgs2<D>;
    };
    struct struct_Windows_UI_Input_CrossSlideThresholds
    {
        float SelectionStart;
        float SpeedBumpStart;
        float SpeedBumpEnd;
        float RearrangeStart;
    };
    template <> struct abi<Windows::UI::Input::CrossSlideThresholds>
    {
        using type = struct_Windows_UI_Input_CrossSlideThresholds;
    };
    struct struct_Windows_UI_Input_ManipulationDelta
    {
        winrt::Windows::Foundation::Point Translation;
        float Scale;
        float Rotation;
        float Expansion;
    };
    template <> struct abi<Windows::UI::Input::ManipulationDelta>
    {
        using type = struct_Windows_UI_Input_ManipulationDelta;
    };
    struct struct_Windows_UI_Input_ManipulationVelocities
    {
        winrt::Windows::Foundation::Point Linear;
        float Angular;
        float Expansion;
    };
    template <> struct abi<Windows::UI::Input::ManipulationVelocities>
    {
        using type = struct_Windows_UI_Input_ManipulationVelocities;
    };
}
#endif
