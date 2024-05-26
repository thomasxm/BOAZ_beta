// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_1_H
#define WINRT_Windows_UI_Core_1_H
#include "winrt/impl/Windows.UI.Core.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    struct __declspec(empty_bases) IAcceleratorKeyEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAcceleratorKeyEventArgs>,
        impl::require<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IAcceleratorKeyEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAcceleratorKeyEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAcceleratorKeyEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAcceleratorKeyEventArgs2>,
        impl::require<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs2, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IAcceleratorKeyEventArgs2(std::nullptr_t = nullptr) noexcept {}
        IAcceleratorKeyEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAutomationProviderRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAutomationProviderRequestedEventArgs>,
        impl::require<winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IAutomationProviderRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAutomationProviderRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBackRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBackRequestedEventArgs>
    {
        IBackRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IBackRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICharacterReceivedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICharacterReceivedEventArgs>,
        impl::require<winrt::Windows::UI::Core::ICharacterReceivedEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        ICharacterReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICharacterReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IClosestInteractiveBoundsRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IClosestInteractiveBoundsRequestedEventArgs>
    {
        IClosestInteractiveBoundsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IClosestInteractiveBoundsRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreAcceleratorKeys :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreAcceleratorKeys>
    {
        ICoreAcceleratorKeys(std::nullptr_t = nullptr) noexcept {}
        ICoreAcceleratorKeys(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreClosestInteractiveBoundsRequested :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreClosestInteractiveBoundsRequested>
    {
        ICoreClosestInteractiveBoundsRequested(std::nullptr_t = nullptr) noexcept {}
        ICoreClosestInteractiveBoundsRequested(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreComponentFocusable :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreComponentFocusable>
    {
        ICoreComponentFocusable(std::nullptr_t = nullptr) noexcept {}
        ICoreComponentFocusable(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreCursor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreCursor>
    {
        ICoreCursor(std::nullptr_t = nullptr) noexcept {}
        ICoreCursor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreCursorFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreCursorFactory>
    {
        ICoreCursorFactory(std::nullptr_t = nullptr) noexcept {}
        ICoreCursorFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreDispatcher :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreDispatcher>,
        impl::require<winrt::Windows::UI::Core::ICoreDispatcher, winrt::Windows::UI::Core::ICoreAcceleratorKeys>
    {
        ICoreDispatcher(std::nullptr_t = nullptr) noexcept {}
        ICoreDispatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreDispatcher2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreDispatcher2>
    {
        ICoreDispatcher2(std::nullptr_t = nullptr) noexcept {}
        ICoreDispatcher2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreDispatcherWithTaskPriority :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreDispatcherWithTaskPriority>
    {
        ICoreDispatcherWithTaskPriority(std::nullptr_t = nullptr) noexcept {}
        ICoreDispatcherWithTaskPriority(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreIndependentInputSourceController :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreIndependentInputSourceController>
    {
        ICoreIndependentInputSourceController(std::nullptr_t = nullptr) noexcept {}
        ICoreIndependentInputSourceController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreIndependentInputSourceControllerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreIndependentInputSourceControllerStatics>
    {
        ICoreIndependentInputSourceControllerStatics(std::nullptr_t = nullptr) noexcept {}
        ICoreIndependentInputSourceControllerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreInputSourceBase :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreInputSourceBase>
    {
        ICoreInputSourceBase(std::nullptr_t = nullptr) noexcept {}
        ICoreInputSourceBase(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreKeyboardInputSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreKeyboardInputSource>
    {
        ICoreKeyboardInputSource(std::nullptr_t = nullptr) noexcept {}
        ICoreKeyboardInputSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreKeyboardInputSource2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreKeyboardInputSource2>
    {
        ICoreKeyboardInputSource2(std::nullptr_t = nullptr) noexcept {}
        ICoreKeyboardInputSource2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICorePointerInputSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICorePointerInputSource>
    {
        ICorePointerInputSource(std::nullptr_t = nullptr) noexcept {}
        ICorePointerInputSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICorePointerInputSource2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICorePointerInputSource2>,
        impl::require<winrt::Windows::UI::Core::ICorePointerInputSource2, winrt::Windows::UI::Core::ICorePointerInputSource>
    {
        ICorePointerInputSource2(std::nullptr_t = nullptr) noexcept {}
        ICorePointerInputSource2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICorePointerRedirector :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICorePointerRedirector>
    {
        ICorePointerRedirector(std::nullptr_t = nullptr) noexcept {}
        ICorePointerRedirector(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreTouchHitTesting :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreTouchHitTesting>
    {
        ICoreTouchHitTesting(std::nullptr_t = nullptr) noexcept {}
        ICoreTouchHitTesting(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindow :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindow>
    {
        ICoreWindow(std::nullptr_t = nullptr) noexcept {}
        ICoreWindow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindow2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindow2>
    {
        ICoreWindow2(std::nullptr_t = nullptr) noexcept {}
        ICoreWindow2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindow3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindow3>
    {
        ICoreWindow3(std::nullptr_t = nullptr) noexcept {}
        ICoreWindow3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindow4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindow4>
    {
        ICoreWindow4(std::nullptr_t = nullptr) noexcept {}
        ICoreWindow4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindow5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindow5>
    {
        ICoreWindow5(std::nullptr_t = nullptr) noexcept {}
        ICoreWindow5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowDialog :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowDialog>
    {
        ICoreWindowDialog(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowDialog(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowDialogFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowDialogFactory>
    {
        ICoreWindowDialogFactory(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowDialogFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowEventArgs>
    {
        ICoreWindowEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowFlyout :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowFlyout>
    {
        ICoreWindowFlyout(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowFlyout(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowFlyoutFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowFlyoutFactory>
    {
        ICoreWindowFlyoutFactory(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowFlyoutFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowPopupShowingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowPopupShowingEventArgs>
    {
        ICoreWindowPopupShowingEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowPopupShowingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowResizeManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowResizeManager>
    {
        ICoreWindowResizeManager(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowResizeManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowResizeManagerLayoutCapability :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowResizeManagerLayoutCapability>
    {
        ICoreWindowResizeManagerLayoutCapability(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowResizeManagerLayoutCapability(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowResizeManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowResizeManagerStatics>
    {
        ICoreWindowResizeManagerStatics(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowResizeManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowStatic :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowStatic>
    {
        ICoreWindowStatic(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowStatic(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICoreWindowWithContext :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICoreWindowWithContext>
    {
        ICoreWindowWithContext(std::nullptr_t = nullptr) noexcept {}
        ICoreWindowWithContext(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IIdleDispatchedHandlerArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IIdleDispatchedHandlerArgs>
    {
        IIdleDispatchedHandlerArgs(std::nullptr_t = nullptr) noexcept {}
        IIdleDispatchedHandlerArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInitializeWithCoreWindow :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInitializeWithCoreWindow>
    {
        IInitializeWithCoreWindow(std::nullptr_t = nullptr) noexcept {}
        IInitializeWithCoreWindow(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IInputEnabledEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IInputEnabledEventArgs>,
        impl::require<winrt::Windows::UI::Core::IInputEnabledEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IInputEnabledEventArgs(std::nullptr_t = nullptr) noexcept {}
        IInputEnabledEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyEventArgs>,
        impl::require<winrt::Windows::UI::Core::IKeyEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IKeyEventArgs(std::nullptr_t = nullptr) noexcept {}
        IKeyEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IKeyEventArgs2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IKeyEventArgs2>,
        impl::require<winrt::Windows::UI::Core::IKeyEventArgs2, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IKeyEventArgs2(std::nullptr_t = nullptr) noexcept {}
        IKeyEventArgs2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPointerEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPointerEventArgs>,
        impl::require<winrt::Windows::UI::Core::IPointerEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IPointerEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPointerEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemNavigationManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemNavigationManager>
    {
        ISystemNavigationManager(std::nullptr_t = nullptr) noexcept {}
        ISystemNavigationManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemNavigationManager2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemNavigationManager2>
    {
        ISystemNavigationManager2(std::nullptr_t = nullptr) noexcept {}
        ISystemNavigationManager2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISystemNavigationManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISystemNavigationManagerStatics>
    {
        ISystemNavigationManagerStatics(std::nullptr_t = nullptr) noexcept {}
        ISystemNavigationManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITouchHitTestingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITouchHitTestingEventArgs>,
        impl::require<winrt::Windows::UI::Core::ITouchHitTestingEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        ITouchHitTestingEventArgs(std::nullptr_t = nullptr) noexcept {}
        ITouchHitTestingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVisibilityChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVisibilityChangedEventArgs>,
        impl::require<winrt::Windows::UI::Core::IVisibilityChangedEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IVisibilityChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IVisibilityChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowActivatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowActivatedEventArgs>,
        impl::require<winrt::Windows::UI::Core::IWindowActivatedEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IWindowActivatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowSizeChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowSizeChangedEventArgs>,
        impl::require<winrt::Windows::UI::Core::IWindowSizeChangedEventArgs, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        IWindowSizeChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowSizeChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
