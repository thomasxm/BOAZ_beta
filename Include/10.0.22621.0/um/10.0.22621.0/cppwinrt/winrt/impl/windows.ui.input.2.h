// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_2_H
#define WINRT_Windows_UI_Input_2_H
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Input.1.h"
WINRT_EXPORT namespace winrt::Windows::UI::Input
{
    struct CrossSlideThresholds
    {
        float SelectionStart;
        float SpeedBumpStart;
        float SpeedBumpEnd;
        float RearrangeStart;
    };
    inline bool operator==(CrossSlideThresholds const& left, CrossSlideThresholds const& right) noexcept
    {
        return left.SelectionStart == right.SelectionStart && left.SpeedBumpStart == right.SpeedBumpStart && left.SpeedBumpEnd == right.SpeedBumpEnd && left.RearrangeStart == right.RearrangeStart;
    }
    inline bool operator!=(CrossSlideThresholds const& left, CrossSlideThresholds const& right) noexcept
    {
        return !(left == right);
    }
    struct ManipulationDelta
    {
        winrt::Windows::Foundation::Point Translation;
        float Scale;
        float Rotation;
        float Expansion;
    };
    inline bool operator==(ManipulationDelta const& left, ManipulationDelta const& right) noexcept
    {
        return left.Translation == right.Translation && left.Scale == right.Scale && left.Rotation == right.Rotation && left.Expansion == right.Expansion;
    }
    inline bool operator!=(ManipulationDelta const& left, ManipulationDelta const& right) noexcept
    {
        return !(left == right);
    }
    struct ManipulationVelocities
    {
        winrt::Windows::Foundation::Point Linear;
        float Angular;
        float Expansion;
    };
    inline bool operator==(ManipulationVelocities const& left, ManipulationVelocities const& right) noexcept
    {
        return left.Linear == right.Linear && left.Angular == right.Angular && left.Expansion == right.Expansion;
    }
    inline bool operator!=(ManipulationVelocities const& left, ManipulationVelocities const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) AttachableInputObject : winrt::Windows::UI::Input::IAttachableInputObject,
        impl::require<AttachableInputObject, winrt::Windows::Foundation::IClosable>
    {
        AttachableInputObject(std::nullptr_t) noexcept {}
        AttachableInputObject(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IAttachableInputObject(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CrossSlidingEventArgs : winrt::Windows::UI::Input::ICrossSlidingEventArgs,
        impl::require<CrossSlidingEventArgs, winrt::Windows::UI::Input::ICrossSlidingEventArgs2>
    {
        CrossSlidingEventArgs(std::nullptr_t) noexcept {}
        CrossSlidingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::ICrossSlidingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DraggingEventArgs : winrt::Windows::UI::Input::IDraggingEventArgs,
        impl::require<DraggingEventArgs, winrt::Windows::UI::Input::IDraggingEventArgs2>
    {
        DraggingEventArgs(std::nullptr_t) noexcept {}
        DraggingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IDraggingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) EdgeGesture : winrt::Windows::UI::Input::IEdgeGesture
    {
        EdgeGesture(std::nullptr_t) noexcept {}
        EdgeGesture(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IEdgeGesture(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
    struct __declspec(empty_bases) EdgeGestureEventArgs : winrt::Windows::UI::Input::IEdgeGestureEventArgs
    {
        EdgeGestureEventArgs(std::nullptr_t) noexcept {}
        EdgeGestureEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IEdgeGestureEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) GestureRecognizer : winrt::Windows::UI::Input::IGestureRecognizer,
        impl::require<GestureRecognizer, winrt::Windows::UI::Input::IGestureRecognizer2>
    {
        GestureRecognizer(std::nullptr_t) noexcept {}
        GestureRecognizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IGestureRecognizer(ptr, take_ownership_from_abi) {}
        GestureRecognizer();
    };
    struct __declspec(empty_bases) HoldingEventArgs : winrt::Windows::UI::Input::IHoldingEventArgs,
        impl::require<HoldingEventArgs, winrt::Windows::UI::Input::IHoldingEventArgs2>
    {
        HoldingEventArgs(std::nullptr_t) noexcept {}
        HoldingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IHoldingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InputActivationListener : winrt::Windows::UI::Input::IInputActivationListener,
        impl::base<InputActivationListener, winrt::Windows::UI::Input::AttachableInputObject>,
        impl::require<InputActivationListener, winrt::Windows::UI::Input::IAttachableInputObject, winrt::Windows::Foundation::IClosable>
    {
        InputActivationListener(std::nullptr_t) noexcept {}
        InputActivationListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IInputActivationListener(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) InputActivationListenerActivationChangedEventArgs : winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs
    {
        InputActivationListenerActivationChangedEventArgs(std::nullptr_t) noexcept {}
        InputActivationListenerActivationChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) KeyboardDeliveryInterceptor : winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor
    {
        KeyboardDeliveryInterceptor(std::nullptr_t) noexcept {}
        KeyboardDeliveryInterceptor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
    struct __declspec(empty_bases) ManipulationCompletedEventArgs : winrt::Windows::UI::Input::IManipulationCompletedEventArgs,
        impl::require<ManipulationCompletedEventArgs, winrt::Windows::UI::Input::IManipulationCompletedEventArgs2>
    {
        ManipulationCompletedEventArgs(std::nullptr_t) noexcept {}
        ManipulationCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IManipulationCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ManipulationInertiaStartingEventArgs : winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs,
        impl::require<ManipulationInertiaStartingEventArgs, winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs2>
    {
        ManipulationInertiaStartingEventArgs(std::nullptr_t) noexcept {}
        ManipulationInertiaStartingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ManipulationStartedEventArgs : winrt::Windows::UI::Input::IManipulationStartedEventArgs,
        impl::require<ManipulationStartedEventArgs, winrt::Windows::UI::Input::IManipulationStartedEventArgs2>
    {
        ManipulationStartedEventArgs(std::nullptr_t) noexcept {}
        ManipulationStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IManipulationStartedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ManipulationUpdatedEventArgs : winrt::Windows::UI::Input::IManipulationUpdatedEventArgs,
        impl::require<ManipulationUpdatedEventArgs, winrt::Windows::UI::Input::IManipulationUpdatedEventArgs2>
    {
        ManipulationUpdatedEventArgs(std::nullptr_t) noexcept {}
        ManipulationUpdatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IManipulationUpdatedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MouseWheelParameters : winrt::Windows::UI::Input::IMouseWheelParameters
    {
        MouseWheelParameters(std::nullptr_t) noexcept {}
        MouseWheelParameters(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IMouseWheelParameters(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PointerPoint : winrt::Windows::UI::Input::IPointerPoint
    {
        PointerPoint(std::nullptr_t) noexcept {}
        PointerPoint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IPointerPoint(ptr, take_ownership_from_abi) {}
        static auto GetCurrentPoint(uint32_t pointerId);
        static auto GetIntermediatePoints(uint32_t pointerId);
        static auto GetCurrentPoint(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform);
        static auto GetIntermediatePoints(uint32_t pointerId, winrt::Windows::UI::Input::IPointerPointTransform const& transform);
    };
    struct __declspec(empty_bases) PointerPointProperties : winrt::Windows::UI::Input::IPointerPointProperties,
        impl::require<PointerPointProperties, winrt::Windows::UI::Input::IPointerPointProperties2>
    {
        PointerPointProperties(std::nullptr_t) noexcept {}
        PointerPointProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IPointerPointProperties(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PointerVisualizationSettings : winrt::Windows::UI::Input::IPointerVisualizationSettings
    {
        PointerVisualizationSettings(std::nullptr_t) noexcept {}
        PointerVisualizationSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IPointerVisualizationSettings(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
    };
    struct __declspec(empty_bases) RadialController : winrt::Windows::UI::Input::IRadialController,
        impl::require<RadialController, winrt::Windows::UI::Input::IRadialController2>
    {
        RadialController(std::nullptr_t) noexcept {}
        RadialController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialController(ptr, take_ownership_from_abi) {}
        static auto IsSupported();
        static auto CreateForCurrentView();
    };
    struct __declspec(empty_bases) RadialControllerButtonClickedEventArgs : winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs,
        impl::require<RadialControllerButtonClickedEventArgs, winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2>
    {
        RadialControllerButtonClickedEventArgs(std::nullptr_t) noexcept {}
        RadialControllerButtonClickedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerButtonHoldingEventArgs : winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs
    {
        RadialControllerButtonHoldingEventArgs(std::nullptr_t) noexcept {}
        RadialControllerButtonHoldingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerButtonPressedEventArgs : winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs
    {
        RadialControllerButtonPressedEventArgs(std::nullptr_t) noexcept {}
        RadialControllerButtonPressedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerButtonReleasedEventArgs : winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs
    {
        RadialControllerButtonReleasedEventArgs(std::nullptr_t) noexcept {}
        RadialControllerButtonReleasedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerConfiguration : winrt::Windows::UI::Input::IRadialControllerConfiguration,
        impl::require<RadialControllerConfiguration, winrt::Windows::UI::Input::IRadialControllerConfiguration2>
    {
        RadialControllerConfiguration(std::nullptr_t) noexcept {}
        RadialControllerConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerConfiguration(ptr, take_ownership_from_abi) {}
        static auto GetForCurrentView();
        static auto AppController(winrt::Windows::UI::Input::RadialController const& value);
        [[nodiscard]] static auto AppController();
        static auto IsAppControllerEnabled(bool value);
        [[nodiscard]] static auto IsAppControllerEnabled();
    };
    struct __declspec(empty_bases) RadialControllerControlAcquiredEventArgs : winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs,
        impl::require<RadialControllerControlAcquiredEventArgs, winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2>
    {
        RadialControllerControlAcquiredEventArgs(std::nullptr_t) noexcept {}
        RadialControllerControlAcquiredEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerMenu : winrt::Windows::UI::Input::IRadialControllerMenu
    {
        RadialControllerMenu(std::nullptr_t) noexcept {}
        RadialControllerMenu(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerMenu(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerMenuItem : winrt::Windows::UI::Input::IRadialControllerMenuItem
    {
        RadialControllerMenuItem(std::nullptr_t) noexcept {}
        RadialControllerMenuItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerMenuItem(ptr, take_ownership_from_abi) {}
        static auto CreateFromIcon(param::hstring const& displayText, winrt::Windows::Storage::Streams::RandomAccessStreamReference const& icon);
        static auto CreateFromKnownIcon(param::hstring const& displayText, winrt::Windows::UI::Input::RadialControllerMenuKnownIcon const& value);
        static auto CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily);
        static auto CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily, winrt::Windows::Foundation::Uri const& fontUri);
    };
    struct __declspec(empty_bases) RadialControllerRotationChangedEventArgs : winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs,
        impl::require<RadialControllerRotationChangedEventArgs, winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2>
    {
        RadialControllerRotationChangedEventArgs(std::nullptr_t) noexcept {}
        RadialControllerRotationChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerScreenContact : winrt::Windows::UI::Input::IRadialControllerScreenContact
    {
        RadialControllerScreenContact(std::nullptr_t) noexcept {}
        RadialControllerScreenContact(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerScreenContact(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerScreenContactContinuedEventArgs : winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs,
        impl::require<RadialControllerScreenContactContinuedEventArgs, winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2>
    {
        RadialControllerScreenContactContinuedEventArgs(std::nullptr_t) noexcept {}
        RadialControllerScreenContactContinuedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerScreenContactEndedEventArgs : winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs
    {
        RadialControllerScreenContactEndedEventArgs(std::nullptr_t) noexcept {}
        RadialControllerScreenContactEndedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RadialControllerScreenContactStartedEventArgs : winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs,
        impl::require<RadialControllerScreenContactStartedEventArgs, winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2>
    {
        RadialControllerScreenContactStartedEventArgs(std::nullptr_t) noexcept {}
        RadialControllerScreenContactStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) RightTappedEventArgs : winrt::Windows::UI::Input::IRightTappedEventArgs,
        impl::require<RightTappedEventArgs, winrt::Windows::UI::Input::IRightTappedEventArgs2>
    {
        RightTappedEventArgs(std::nullptr_t) noexcept {}
        RightTappedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::IRightTappedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemButtonEventController : winrt::Windows::UI::Input::ISystemButtonEventController,
        impl::base<SystemButtonEventController, winrt::Windows::UI::Input::AttachableInputObject>,
        impl::require<SystemButtonEventController, winrt::Windows::UI::Input::IAttachableInputObject, winrt::Windows::Foundation::IClosable>
    {
        SystemButtonEventController(std::nullptr_t) noexcept {}
        SystemButtonEventController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::ISystemButtonEventController(ptr, take_ownership_from_abi) {}
        static auto CreateForDispatcherQueue(winrt::Windows::System::DispatcherQueue const& queue);
    };
    struct __declspec(empty_bases) SystemFunctionButtonEventArgs : winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs
    {
        SystemFunctionButtonEventArgs(std::nullptr_t) noexcept {}
        SystemFunctionButtonEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::ISystemFunctionButtonEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemFunctionLockChangedEventArgs : winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs
    {
        SystemFunctionLockChangedEventArgs(std::nullptr_t) noexcept {}
        SystemFunctionLockChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::ISystemFunctionLockChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SystemFunctionLockIndicatorChangedEventArgs : winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs
    {
        SystemFunctionLockIndicatorChangedEventArgs(std::nullptr_t) noexcept {}
        SystemFunctionLockIndicatorChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::ISystemFunctionLockIndicatorChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) TappedEventArgs : winrt::Windows::UI::Input::ITappedEventArgs,
        impl::require<TappedEventArgs, winrt::Windows::UI::Input::ITappedEventArgs2>
    {
        TappedEventArgs(std::nullptr_t) noexcept {}
        TappedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::UI::Input::ITappedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
