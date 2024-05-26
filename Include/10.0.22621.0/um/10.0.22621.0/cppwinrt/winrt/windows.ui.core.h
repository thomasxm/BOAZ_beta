// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_H
#define WINRT_Windows_UI_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreAcceleratorKeyEventType) consume_Windows_UI_Core_IAcceleratorKeyEventArgs<D>::EventType() const
    {
        winrt::Windows::UI::Core::CoreAcceleratorKeyEventType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IAcceleratorKeyEventArgs)->get_EventType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_UI_Core_IAcceleratorKeyEventArgs<D>::VirtualKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IAcceleratorKeyEventArgs)->get_VirtualKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CorePhysicalKeyStatus) consume_Windows_UI_Core_IAcceleratorKeyEventArgs<D>::KeyStatus() const
    {
        winrt::Windows::UI::Core::CorePhysicalKeyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IAcceleratorKeyEventArgs)->get_KeyStatus(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_IAcceleratorKeyEventArgs2<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IAcceleratorKeyEventArgs2)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Core_IAutomationProviderRequestedEventArgs<D>::AutomationProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs)->get_AutomationProvider(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_IAutomationProviderRequestedEventArgs<D>::AutomationProvider(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs)->put_AutomationProvider(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_IBackRequestedEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IBackRequestedEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_IBackRequestedEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IBackRequestedEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Core_ICharacterReceivedEventArgs<D>::KeyCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICharacterReceivedEventArgs)->get_KeyCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CorePhysicalKeyStatus) consume_Windows_UI_Core_ICharacterReceivedEventArgs<D>::KeyStatus() const
    {
        winrt::Windows::UI::Core::CorePhysicalKeyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICharacterReceivedEventArgs)->get_KeyStatus(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::PointerPosition() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->get_PointerPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::SearchBounds() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->get_SearchBounds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::ClosestInteractiveBounds() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->get_ClosestInteractiveBounds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::ClosestInteractiveBounds(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->put_ClosestInteractiveBounds(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreDispatcher, winrt::Windows::UI::Core::AcceleratorKeyEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreAcceleratorKeys)->add_AcceleratorKeyActivated(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated_revoker consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreDispatcher, winrt::Windows::UI::Core::AcceleratorKeyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AcceleratorKeyActivated_revoker>(this, AcceleratorKeyActivated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreAcceleratorKeys)->remove_AcceleratorKeyActivated(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreComponentInputSource, winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreClosestInteractiveBoundsRequested)->add_ClosestInteractiveBoundsRequested(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested_revoker consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreComponentInputSource, winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ClosestInteractiveBoundsRequested_revoker>(this, ClosestInteractiveBoundsRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreClosestInteractiveBoundsRequested)->remove_ClosestInteractiveBoundsRequested(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreComponentFocusable<D>::HasFocus() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreComponentFocusable)->get_HasFocus(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CoreWindowEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreComponentFocusable)->add_GotFocus(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus_revoker consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CoreWindowEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreComponentFocusable)->remove_GotFocus(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CoreWindowEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreComponentFocusable)->add_LostFocus(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus_revoker consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CoreWindowEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreComponentFocusable)->remove_LostFocus(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Core_ICoreCursor<D>::Id() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreCursor)->get_Id(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreCursorType) consume_Windows_UI_Core_ICoreCursor<D>::Type() const
    {
        winrt::Windows::UI::Core::CoreCursorType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreCursor)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreCursor) consume_Windows_UI_Core_ICoreCursorFactory<D>::CreateCursor(winrt::Windows::UI::Core::CoreCursorType const& type, uint32_t id) const
    {
        void* cursor{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreCursorFactory)->CreateCursor(static_cast<int32_t>(type), id, &cursor));
        return winrt::Windows::UI::Core::CoreCursor{ cursor, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreDispatcher<D>::HasThreadAccess() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcher)->get_HasThreadAccess(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreDispatcher<D>::ProcessEvents(winrt::Windows::UI::Core::CoreProcessEventsOption const& options) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcher)->ProcessEvents(static_cast<int32_t>(options)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Core_ICoreDispatcher<D>::RunAsync(winrt::Windows::UI::Core::CoreDispatcherPriority const& priority, winrt::Windows::UI::Core::DispatchedHandler const& agileCallback) const
    {
        void* asyncAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcher)->RunAsync(static_cast<int32_t>(priority), *(void**)(&agileCallback), &asyncAction));
        return winrt::Windows::Foundation::IAsyncAction{ asyncAction, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Core_ICoreDispatcher<D>::RunIdleAsync(winrt::Windows::UI::Core::IdleDispatchedHandler const& agileCallback) const
    {
        void* asyncAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcher)->RunIdleAsync(*(void**)(&agileCallback), &asyncAction));
        return winrt::Windows::Foundation::IAsyncAction{ asyncAction, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Core_ICoreDispatcher2<D>::TryRunAsync(winrt::Windows::UI::Core::CoreDispatcherPriority const& priority, winrt::Windows::UI::Core::DispatchedHandler const& agileCallback) const
    {
        void* asyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcher2)->TryRunAsync(static_cast<int32_t>(priority), *(void**)(&agileCallback), &asyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ asyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_UI_Core_ICoreDispatcher2<D>::TryRunIdleAsync(winrt::Windows::UI::Core::IdleDispatchedHandler const& agileCallback) const
    {
        void* asyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcher2)->TryRunIdleAsync(*(void**)(&agileCallback), &asyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ asyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreDispatcherPriority) consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::CurrentPriority() const
    {
        winrt::Windows::UI::Core::CoreDispatcherPriority value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority)->get_CurrentPriority(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::CurrentPriority(winrt::Windows::UI::Core::CoreDispatcherPriority const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority)->put_CurrentPriority(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::ShouldYield() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority)->ShouldYield(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::ShouldYield(winrt::Windows::UI::Core::CoreDispatcherPriority const& priority) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority)->ShouldYieldToPriority(static_cast<int32_t>(priority), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::StopProcessEvents() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority)->StopProcessEvents());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreIndependentInputSourceController<D>::IsTransparentForUncontrolledInput() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceController)->get_IsTransparentForUncontrolledInput(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreIndependentInputSourceController<D>::IsTransparentForUncontrolledInput(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceController)->put_IsTransparentForUncontrolledInput(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreIndependentInputSourceController<D>::IsPalmRejectionEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceController)->get_IsPalmRejectionEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreIndependentInputSourceController<D>::IsPalmRejectionEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceController)->put_IsPalmRejectionEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreIndependentInputSource) consume_Windows_UI_Core_ICoreIndependentInputSourceController<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceController)->get_Source(&value));
        return winrt::Windows::UI::Core::CoreIndependentInputSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreIndependentInputSourceController<D>::SetControlledInput(winrt::Windows::UI::Core::CoreInputDeviceTypes const& inputTypes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceController)->SetControlledInput(static_cast<uint32_t>(inputTypes)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreIndependentInputSourceController<D>::SetControlledInput(winrt::Windows::UI::Core::CoreInputDeviceTypes const& inputTypes, winrt::Windows::UI::Core::CoreIndependentInputFilters const& required, winrt::Windows::UI::Core::CoreIndependentInputFilters const& excluded) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceController)->SetControlledInputWithFilters(static_cast<uint32_t>(inputTypes), static_cast<uint32_t>(required), static_cast<uint32_t>(excluded)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreIndependentInputSourceController) consume_Windows_UI_Core_ICoreIndependentInputSourceControllerStatics<D>::CreateForVisual(winrt::Windows::UI::Composition::Visual const& visual) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceControllerStatics)->CreateForVisual(*(void**)(&visual), &result));
        return winrt::Windows::UI::Core::CoreIndependentInputSourceController{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreIndependentInputSourceController) consume_Windows_UI_Core_ICoreIndependentInputSourceControllerStatics<D>::CreateForIVisualElement(winrt::Windows::UI::Composition::IVisualElement const& visualElement) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreIndependentInputSourceControllerStatics)->CreateForIVisualElement(*(void**)(&visualElement), &result));
        return winrt::Windows::UI::Core::CoreIndependentInputSourceController{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreDispatcher) consume_Windows_UI_Core_ICoreInputSourceBase<D>::Dispatcher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreInputSourceBase)->get_Dispatcher(&value));
        return winrt::Windows::UI::Core::CoreDispatcher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreInputSourceBase<D>::IsInputEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreInputSourceBase)->get_IsInputEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreInputSourceBase<D>::IsInputEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreInputSourceBase)->put_IsInputEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::InputEnabledEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreInputSourceBase)->add_InputEnabled(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled_revoker consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::InputEnabledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, InputEnabled_revoker>(this, InputEnabled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreInputSourceBase)->remove_InputEnabled(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreVirtualKeyStates) consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::GetCurrentKeyState(winrt::Windows::System::VirtualKey const& virtualKey) const
    {
        winrt::Windows::UI::Core::CoreVirtualKeyStates KeyState{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource)->GetCurrentKeyState(static_cast<int32_t>(virtualKey), reinterpret_cast<uint32_t*>(&KeyState)));
        return KeyState;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource)->add_CharacterReceived(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived_revoker consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CharacterReceived_revoker>(this, CharacterReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource)->remove_CharacterReceived(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource)->add_KeyDown(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown_revoker consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource)->remove_KeyDown(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource)->add_KeyUp(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp_revoker consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource)->remove_KeyUp(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_ICoreKeyboardInputSource2<D>::GetCurrentKeyEventDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreKeyboardInputSource2)->GetCurrentKeyEventDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::ReleasePointerCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->ReleasePointerCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::SetPointerCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->SetPointerCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICorePointerInputSource<D>::HasCapture() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->get_HasCapture(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPosition() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->get_PointerPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreCursor) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCursor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->get_PointerCursor(&value));
        return winrt::Windows::UI::Core::CoreCursor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCursor(winrt::Windows::UI::Core::CoreCursor const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->put_PointerCursor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->add_PointerCaptureLost(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerCaptureLost_revoker>(this, PointerCaptureLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->remove_PointerCaptureLost(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->add_PointerEntered(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->remove_PointerEntered(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->add_PointerExited(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->remove_PointerExited(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->add_PointerMoved(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->remove_PointerMoved(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->add_PointerPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->remove_PointerPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->add_PointerReleased(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->remove_PointerReleased(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->add_PointerWheelChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerWheelChanged_revoker>(this, PointerWheelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource)->remove_PointerWheelChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) consume_Windows_UI_Core_ICorePointerInputSource2<D>::DispatcherQueue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerInputSource2)->get_DispatcherQueue(&value));
        return winrt::Windows::System::DispatcherQueue{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerRedirector)->add_PointerRoutedAway(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway_revoker consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerRoutedAway_revoker>(this, PointerRoutedAway(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerRedirector)->remove_PointerRoutedAway(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerRedirector)->add_PointerRoutedTo(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo_revoker consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerRoutedTo_revoker>(this, PointerRoutedTo(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerRedirector)->remove_PointerRoutedTo(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerRedirector)->add_PointerRoutedReleased(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased_revoker consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerRoutedReleased_revoker>(this, PointerRoutedReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICorePointerRedirector)->remove_PointerRoutedReleased(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreTouchHitTesting)->add_TouchHitTesting(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting_revoker consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TouchHitTesting_revoker>(this, TouchHitTesting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreTouchHitTesting)->remove_TouchHitTesting(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Core_ICoreWindow<D>::AutomationHostProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_AutomationHostProvider(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Core_ICoreWindow<D>::Bounds() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_Bounds(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_UI_Core_ICoreWindow<D>::CustomProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_CustomProperties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreDispatcher) consume_Windows_UI_Core_ICoreWindow<D>::Dispatcher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_Dispatcher(&value));
        return winrt::Windows::UI::Core::CoreDispatcher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindowFlowDirection) consume_Windows_UI_Core_ICoreWindow<D>::FlowDirection() const
    {
        winrt::Windows::UI::Core::CoreWindowFlowDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_FlowDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::FlowDirection(winrt::Windows::UI::Core::CoreWindowFlowDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->put_FlowDirection(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreWindow<D>::IsInputEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_IsInputEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::IsInputEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->put_IsInputEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreCursor) consume_Windows_UI_Core_ICoreWindow<D>::PointerCursor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_PointerCursor(&value));
        return winrt::Windows::UI::Core::CoreCursor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerCursor(winrt::Windows::UI::Core::CoreCursor const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->put_PointerCursor(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Core_ICoreWindow<D>::PointerPosition() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_PointerPosition(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreWindow<D>::Visible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->get_Visible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::Activate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->Activate());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreVirtualKeyStates) consume_Windows_UI_Core_ICoreWindow<D>::GetAsyncKeyState(winrt::Windows::System::VirtualKey const& virtualKey) const
    {
        winrt::Windows::UI::Core::CoreVirtualKeyStates KeyState{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->GetAsyncKeyState(static_cast<int32_t>(virtualKey), reinterpret_cast<uint32_t*>(&KeyState)));
        return KeyState;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreVirtualKeyStates) consume_Windows_UI_Core_ICoreWindow<D>::GetKeyState(winrt::Windows::System::VirtualKey const& virtualKey) const
    {
        winrt::Windows::UI::Core::CoreVirtualKeyStates KeyState{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->GetKeyState(static_cast<int32_t>(virtualKey), reinterpret_cast<uint32_t*>(&KeyState)));
        return KeyState;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::ReleasePointerCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->ReleasePointerCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::SetPointerCapture() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->SetPointerCapture());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::Activated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::WindowActivatedEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_Activated(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::Activated_revoker consume_Windows_UI_Core_ICoreWindow<D>::Activated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::WindowActivatedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::Activated(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_Activated(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::AutomationProviderRequestedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_AutomationProviderRequested(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested_revoker consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::AutomationProviderRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AutomationProviderRequested_revoker>(this, AutomationProviderRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_AutomationProviderRequested(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_CharacterReceived(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived_revoker consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CharacterReceived_revoker>(this, CharacterReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_CharacterReceived(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_Closed(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::Closed_revoker consume_Windows_UI_Core_ICoreWindow<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::Closed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_Closed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::InputEnabledEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_InputEnabled(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled_revoker consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::InputEnabledEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, InputEnabled_revoker>(this, InputEnabled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_InputEnabled(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::KeyDown(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_KeyDown(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::KeyDown_revoker consume_Windows_UI_Core_ICoreWindow<D>::KeyDown(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::KeyDown(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_KeyDown(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::KeyUp(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_KeyUp(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::KeyUp_revoker consume_Windows_UI_Core_ICoreWindow<D>::KeyUp(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::KeyEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::KeyUp(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_KeyUp(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_PointerCaptureLost(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerCaptureLost_revoker>(this, PointerCaptureLost(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_PointerCaptureLost(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_PointerEntered(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_PointerEntered(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::PointerExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_PointerExited(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerExited_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerExited(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_PointerExited(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_PointerMoved(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_PointerMoved(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_PointerPressed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_PointerPressed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_PointerReleased(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_PointerReleased(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_TouchHitTesting(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting_revoker consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TouchHitTesting_revoker>(this, TouchHitTesting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_TouchHitTesting(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_PointerWheelChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PointerWheelChanged_revoker>(this, PointerWheelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_PointerWheelChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::WindowSizeChangedEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_SizeChanged(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged_revoker consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::WindowSizeChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_SizeChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::VisibilityChangedEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->add_VisibilityChanged(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged_revoker consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::VisibilityChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, VisibilityChanged_revoker>(this, VisibilityChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow)->remove_VisibilityChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow2<D>::PointerPosition(winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow2)->put_PointerPosition(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow3)->add_ClosestInteractiveBoundsRequested(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested_revoker consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ClosestInteractiveBoundsRequested_revoker>(this, ClosestInteractiveBoundsRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow3)->remove_ClosestInteractiveBoundsRequested(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_ICoreWindow3<D>::GetCurrentKeyEventDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow3)->GetCurrentKeyEventDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow4)->add_ResizeStarted(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted_revoker consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ResizeStarted_revoker>(this, ResizeStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow4)->remove_ResizeStarted(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token pCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow4)->add_ResizeCompleted(*(void**)(&handler), put_abi(pCookie)));
        return pCookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted_revoker consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ResizeCompleted_revoker>(this, ResizeCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow4)->remove_ResizeCompleted(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) consume_Windows_UI_Core_ICoreWindow5<D>::DispatcherQueue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow5)->get_DispatcherQueue(&value));
        return winrt::Windows::System::DispatcherQueue{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindowActivationMode) consume_Windows_UI_Core_ICoreWindow5<D>::ActivationMode() const
    {
        winrt::Windows::UI::Core::CoreWindowActivationMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindow5)->get_ActivationMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->add_Showing(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing_revoker consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Showing_revoker>(this, Showing(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->remove_Showing(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Core_ICoreWindowDialog<D>::MaxSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_MaxSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Core_ICoreWindowDialog<D>::MinSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_MinSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_ICoreWindowDialog<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowDialog<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Core_ICoreWindowDialog<D>::IsInteractionDelayed() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_IsInteractionDelayed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowDialog<D>::IsInteractionDelayed(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->put_IsInteractionDelayed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Popups::IUICommand>) consume_Windows_UI_Core_ICoreWindowDialog<D>::Commands() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_Commands(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Popups::IUICommand>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Core_ICoreWindowDialog<D>::DefaultCommandIndex() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_DefaultCommandIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowDialog<D>::DefaultCommandIndex(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->put_DefaultCommandIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Core_ICoreWindowDialog<D>::CancelCommandIndex() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_CancelCommandIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowDialog<D>::CancelCommandIndex(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->put_CancelCommandIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Popups::UICommandInvokedHandler) consume_Windows_UI_Core_ICoreWindowDialog<D>::BackButtonCommand() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->get_BackButtonCommand(&value));
        return winrt::Windows::UI::Popups::UICommandInvokedHandler{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowDialog<D>::BackButtonCommand(winrt::Windows::UI::Popups::UICommandInvokedHandler const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->put_BackButtonCommand(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Popups::IUICommand>) consume_Windows_UI_Core_ICoreWindowDialog<D>::ShowAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialog)->ShowAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Popups::IUICommand>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindowDialog) consume_Windows_UI_Core_ICoreWindowDialogFactory<D>::CreateWithTitle(param::hstring const& title) const
    {
        void* coreWindowDialog{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowDialogFactory)->CreateWithTitle(*(void**)(&title), &coreWindowDialog));
        return winrt::Windows::UI::Core::CoreWindowDialog{ coreWindowDialog, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreWindowEventArgs<D>::Handled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowEventArgs)->get_Handled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowEventArgs<D>::Handled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowEventArgs)->put_Handled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->add_Showing(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing_revoker consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Showing_revoker>(this, Showing(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->remove_Showing(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Core_ICoreWindowFlyout<D>::MaxSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->get_MaxSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Core_ICoreWindowFlyout<D>::MinSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->get_MinSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_ICoreWindowFlyout<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowFlyout<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Core_ICoreWindowFlyout<D>::IsInteractionDelayed() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->get_IsInteractionDelayed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowFlyout<D>::IsInteractionDelayed(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->put_IsInteractionDelayed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Popups::IUICommand>) consume_Windows_UI_Core_ICoreWindowFlyout<D>::Commands() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->get_Commands(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Popups::IUICommand>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Core_ICoreWindowFlyout<D>::DefaultCommandIndex() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->get_DefaultCommandIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowFlyout<D>::DefaultCommandIndex(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->put_DefaultCommandIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Popups::UICommandInvokedHandler) consume_Windows_UI_Core_ICoreWindowFlyout<D>::BackButtonCommand() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->get_BackButtonCommand(&value));
        return winrt::Windows::UI::Popups::UICommandInvokedHandler{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowFlyout<D>::BackButtonCommand(winrt::Windows::UI::Popups::UICommandInvokedHandler const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->put_BackButtonCommand(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Popups::IUICommand>) consume_Windows_UI_Core_ICoreWindowFlyout<D>::ShowAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyout)->ShowAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Popups::IUICommand>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindowFlyout) consume_Windows_UI_Core_ICoreWindowFlyoutFactory<D>::Create(winrt::Windows::Foundation::Point const& position) const
    {
        void* coreWindowFlyout{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyoutFactory)->Create(impl::bind_in(position), &coreWindowFlyout));
        return winrt::Windows::UI::Core::CoreWindowFlyout{ coreWindowFlyout, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindowFlyout) consume_Windows_UI_Core_ICoreWindowFlyoutFactory<D>::CreateWithTitle(winrt::Windows::Foundation::Point const& position, param::hstring const& title) const
    {
        void* coreWindowFlyout{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowFlyoutFactory)->CreateWithTitle(impl::bind_in(position), *(void**)(&title), &coreWindowFlyout));
        return winrt::Windows::UI::Core::CoreWindowFlyout{ coreWindowFlyout, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowPopupShowingEventArgs<D>::SetDesiredSize(winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowPopupShowingEventArgs)->SetDesiredSize(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowResizeManager<D>::NotifyLayoutCompleted() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowResizeManager)->NotifyLayoutCompleted());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ICoreWindowResizeManagerLayoutCapability<D>::ShouldWaitForLayoutCompletion(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability)->put_ShouldWaitForLayoutCompletion(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_ICoreWindowResizeManagerLayoutCapability<D>::ShouldWaitForLayoutCompletion() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability)->get_ShouldWaitForLayoutCompletion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindowResizeManager) consume_Windows_UI_Core_ICoreWindowResizeManagerStatics<D>::GetForCurrentView() const
    {
        void* CoreWindowResizeManager{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowResizeManagerStatics)->GetForCurrentView(&CoreWindowResizeManager));
        return winrt::Windows::UI::Core::CoreWindowResizeManager{ CoreWindowResizeManager, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindow) consume_Windows_UI_Core_ICoreWindowStatic<D>::GetForCurrentThread() const
    {
        void* ppWindow{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowStatic)->GetForCurrentThread(&ppWindow));
        return winrt::Windows::UI::Core::CoreWindow{ ppWindow, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIContext) consume_Windows_UI_Core_ICoreWindowWithContext<D>::UIContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ICoreWindowWithContext)->get_UIContext(&value));
        return winrt::Windows::UI::UIContext{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_IIdleDispatchedHandlerArgs<D>::IsDispatcherIdle() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IIdleDispatchedHandlerArgs)->get_IsDispatcherIdle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_IInitializeWithCoreWindow<D>::Initialize(winrt::Windows::UI::Core::CoreWindow const& window) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IInitializeWithCoreWindow)->Initialize(*(void**)(&window)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_IInputEnabledEventArgs<D>::InputEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IInputEnabledEventArgs)->get_InputEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKey) consume_Windows_UI_Core_IKeyEventArgs<D>::VirtualKey() const
    {
        winrt::Windows::System::VirtualKey value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IKeyEventArgs)->get_VirtualKey(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CorePhysicalKeyStatus) consume_Windows_UI_Core_IKeyEventArgs<D>::KeyStatus() const
    {
        winrt::Windows::UI::Core::CorePhysicalKeyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IKeyEventArgs)->get_KeyStatus(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Core_IKeyEventArgs2<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IKeyEventArgs2)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::PointerPoint) consume_Windows_UI_Core_IPointerEventArgs<D>::CurrentPoint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IPointerEventArgs)->get_CurrentPoint(&value));
        return winrt::Windows::UI::Input::PointerPoint{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::VirtualKeyModifiers) consume_Windows_UI_Core_IPointerEventArgs<D>::KeyModifiers() const
    {
        winrt::Windows::System::VirtualKeyModifiers value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IPointerEventArgs)->get_KeyModifiers(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>) consume_Windows_UI_Core_IPointerEventArgs<D>::GetIntermediatePoints() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IPointerEventArgs)->GetIntermediatePoints(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested(winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Core::BackRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ISystemNavigationManager)->add_BackRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested_revoker consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Core::BackRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, BackRequested_revoker>(this, BackRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ISystemNavigationManager)->remove_BackRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::AppViewBackButtonVisibility) consume_Windows_UI_Core_ISystemNavigationManager2<D>::AppViewBackButtonVisibility() const
    {
        winrt::Windows::UI::Core::AppViewBackButtonVisibility value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ISystemNavigationManager2)->get_AppViewBackButtonVisibility(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ISystemNavigationManager2<D>::AppViewBackButtonVisibility(winrt::Windows::UI::Core::AppViewBackButtonVisibility const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ISystemNavigationManager2)->put_AppViewBackButtonVisibility(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::SystemNavigationManager) consume_Windows_UI_Core_ISystemNavigationManagerStatics<D>::GetForCurrentView() const
    {
        void* loader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ISystemNavigationManagerStatics)->GetForCurrentView(&loader));
        return winrt::Windows::UI::Core::SystemNavigationManager{ loader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreProximityEvaluation) consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::ProximityEvaluation() const
    {
        winrt::Windows::UI::Core::CoreProximityEvaluation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ITouchHitTestingEventArgs)->get_ProximityEvaluation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::ProximityEvaluation(winrt::Windows::UI::Core::CoreProximityEvaluation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ITouchHitTestingEventArgs)->put_ProximityEvaluation(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::Point() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ITouchHitTestingEventArgs)->get_Point(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::BoundingBox() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ITouchHitTestingEventArgs)->get_BoundingBox(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreProximityEvaluation) consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::EvaluateProximity(winrt::Windows::Foundation::Rect const& controlBoundingBox) const
    {
        winrt::Windows::UI::Core::CoreProximityEvaluation proximityEvaluation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ITouchHitTestingEventArgs)->EvaluateProximityToRect(impl::bind_in(controlBoundingBox), put_abi(proximityEvaluation)));
        return proximityEvaluation;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreProximityEvaluation) consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::EvaluateProximity(array_view<winrt::Windows::Foundation::Point const> controlVertices) const
    {
        winrt::Windows::UI::Core::CoreProximityEvaluation proximityEvaluation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::ITouchHitTestingEventArgs)->EvaluateProximityToPolygon(controlVertices.size(), get_abi(controlVertices), put_abi(proximityEvaluation)));
        return proximityEvaluation;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Core_IVisibilityChangedEventArgs<D>::Visible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IVisibilityChangedEventArgs)->get_Visible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreWindowActivationState) consume_Windows_UI_Core_IWindowActivatedEventArgs<D>::WindowActivationState() const
    {
        winrt::Windows::UI::Core::CoreWindowActivationState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IWindowActivatedEventArgs)->get_WindowActivationState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_UI_Core_IWindowSizeChangedEventArgs<D>::Size() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::IWindowSizeChangedEventArgs)->get_Size(put_abi(value)));
        return value;
    }
    template <typename H> struct delegate<winrt::Windows::UI::Core::DispatchedHandler, H> final : implements_delegate<winrt::Windows::UI::Core::DispatchedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Core::DispatchedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke() noexcept final try
        {
            (*this)();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Core::IdleDispatchedHandler, H> final : implements_delegate<winrt::Windows::UI::Core::IdleDispatchedHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Core::IdleDispatchedHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::UI::Core::IdleDispatchedHandlerArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IAcceleratorKeyEventArgs> : produce_base<D, winrt::Windows::UI::Core::IAcceleratorKeyEventArgs>
    {
        int32_t __stdcall get_EventType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreAcceleratorKeyEventType>(this->shim().EventType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VirtualKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IAcceleratorKeyEventArgs2> : produce_base<D, winrt::Windows::UI::Core::IAcceleratorKeyEventArgs2>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs>
    {
        int32_t __stdcall get_AutomationProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().AutomationProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutomationProvider(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutomationProvider(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IBackRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Core::IBackRequestedEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICharacterReceivedEventArgs> : produce_base<D, winrt::Windows::UI::Core::ICharacterReceivedEventArgs>
    {
        int32_t __stdcall get_KeyCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().KeyCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs> : produce_base<D, winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs>
    {
        int32_t __stdcall get_PointerPosition(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().PointerPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SearchBounds(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().SearchBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClosestInteractiveBounds(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().ClosestInteractiveBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ClosestInteractiveBounds(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosestInteractiveBounds(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreAcceleratorKeys> : produce_base<D, winrt::Windows::UI::Core::ICoreAcceleratorKeys>
    {
        int32_t __stdcall add_AcceleratorKeyActivated(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().AcceleratorKeyActivated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreDispatcher, winrt::Windows::UI::Core::AcceleratorKeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AcceleratorKeyActivated(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcceleratorKeyActivated(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreClosestInteractiveBoundsRequested> : produce_base<D, winrt::Windows::UI::Core::ICoreClosestInteractiveBoundsRequested>
    {
        int32_t __stdcall add_ClosestInteractiveBoundsRequested(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreComponentInputSource, winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ClosestInteractiveBoundsRequested(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreComponentFocusable> : produce_base<D, winrt::Windows::UI::Core::ICoreComponentFocusable>
    {
        int32_t __stdcall get_HasFocus(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_GotFocus(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CoreWindowEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_GotFocus(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_LostFocus(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CoreWindowEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_LostFocus(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreCursor> : produce_base<D, winrt::Windows::UI::Core::ICoreCursor>
    {
        int32_t __stdcall get_Id(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreCursorType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreCursorFactory> : produce_base<D, winrt::Windows::UI::Core::ICoreCursorFactory>
    {
        int32_t __stdcall CreateCursor(int32_t type, uint32_t id, void** cursor) noexcept final try
        {
            clear_abi(cursor);
            typename D::abi_guard guard(this->shim());
            *cursor = detach_from<winrt::Windows::UI::Core::CoreCursor>(this->shim().CreateCursor(*reinterpret_cast<winrt::Windows::UI::Core::CoreCursorType const*>(&type), id));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreDispatcher> : produce_base<D, winrt::Windows::UI::Core::ICoreDispatcher>
    {
        int32_t __stdcall get_HasThreadAccess(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasThreadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessEvents(int32_t options) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessEvents(*reinterpret_cast<winrt::Windows::UI::Core::CoreProcessEventsOption const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RunAsync(int32_t priority, void* agileCallback, void** asyncAction) noexcept final try
        {
            clear_abi(asyncAction);
            typename D::abi_guard guard(this->shim());
            *asyncAction = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<winrt::Windows::UI::Core::CoreDispatcherPriority const*>(&priority), *reinterpret_cast<winrt::Windows::UI::Core::DispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RunIdleAsync(void* agileCallback, void** asyncAction) noexcept final try
        {
            clear_abi(asyncAction);
            typename D::abi_guard guard(this->shim());
            *asyncAction = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RunIdleAsync(*reinterpret_cast<winrt::Windows::UI::Core::IdleDispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreDispatcher2> : produce_base<D, winrt::Windows::UI::Core::ICoreDispatcher2>
    {
        int32_t __stdcall TryRunAsync(int32_t priority, void* agileCallback, void** asyncOperation) noexcept final try
        {
            clear_abi(asyncOperation);
            typename D::abi_guard guard(this->shim());
            *asyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRunAsync(*reinterpret_cast<winrt::Windows::UI::Core::CoreDispatcherPriority const*>(&priority), *reinterpret_cast<winrt::Windows::UI::Core::DispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryRunIdleAsync(void* agileCallback, void** asyncOperation) noexcept final try
        {
            clear_abi(asyncOperation);
            typename D::abi_guard guard(this->shim());
            *asyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRunIdleAsync(*reinterpret_cast<winrt::Windows::UI::Core::IdleDispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority> : produce_base<D, winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority>
    {
        int32_t __stdcall get_CurrentPriority(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreDispatcherPriority>(this->shim().CurrentPriority());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CurrentPriority(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentPriority(*reinterpret_cast<winrt::Windows::UI::Core::CoreDispatcherPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShouldYield(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldYield());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShouldYieldToPriority(int32_t priority, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldYield(*reinterpret_cast<winrt::Windows::UI::Core::CoreDispatcherPriority const*>(&priority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopProcessEvents() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopProcessEvents();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreIndependentInputSourceController> : produce_base<D, winrt::Windows::UI::Core::ICoreIndependentInputSourceController>
    {
        int32_t __stdcall get_IsTransparentForUncontrolledInput(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTransparentForUncontrolledInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTransparentForUncontrolledInput(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTransparentForUncontrolledInput(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPalmRejectionEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPalmRejectionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPalmRejectionEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPalmRejectionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreIndependentInputSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetControlledInput(uint32_t inputTypes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetControlledInput(*reinterpret_cast<winrt::Windows::UI::Core::CoreInputDeviceTypes const*>(&inputTypes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetControlledInputWithFilters(uint32_t inputTypes, uint32_t required, uint32_t excluded) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetControlledInput(*reinterpret_cast<winrt::Windows::UI::Core::CoreInputDeviceTypes const*>(&inputTypes), *reinterpret_cast<winrt::Windows::UI::Core::CoreIndependentInputFilters const*>(&required), *reinterpret_cast<winrt::Windows::UI::Core::CoreIndependentInputFilters const*>(&excluded));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreIndependentInputSourceControllerStatics> : produce_base<D, winrt::Windows::UI::Core::ICoreIndependentInputSourceControllerStatics>
    {
        int32_t __stdcall CreateForVisual(void* visual, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Core::CoreIndependentInputSourceController>(this->shim().CreateForVisual(*reinterpret_cast<winrt::Windows::UI::Composition::Visual const*>(&visual)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForIVisualElement(void* visualElement, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Core::CoreIndependentInputSourceController>(this->shim().CreateForIVisualElement(*reinterpret_cast<winrt::Windows::UI::Composition::IVisualElement const*>(&visualElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreInputSourceBase> : produce_base<D, winrt::Windows::UI::Core::ICoreInputSourceBase>
    {
        int32_t __stdcall get_Dispatcher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
        int32_t __stdcall add_InputEnabled(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().InputEnabled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::InputEnabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_InputEnabled(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InputEnabled(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreKeyboardInputSource> : produce_base<D, winrt::Windows::UI::Core::ICoreKeyboardInputSource>
    {
        int32_t __stdcall GetCurrentKeyState(int32_t virtualKey, uint32_t* KeyState) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *KeyState = detach_from<winrt::Windows::UI::Core::CoreVirtualKeyStates>(this->shim().GetCurrentKeyState(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&virtualKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CharacterReceived(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().CharacterReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::CharacterReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CharacterReceived(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterReceived(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_KeyDown(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyDown(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_KeyUp(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyUp(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreKeyboardInputSource2> : produce_base<D, winrt::Windows::UI::Core::ICoreKeyboardInputSource2>
    {
        int32_t __stdcall GetCurrentKeyEventDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetCurrentKeyEventDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICorePointerInputSource> : produce_base<D, winrt::Windows::UI::Core::ICorePointerInputSource>
    {
        int32_t __stdcall ReleasePointerCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleasePointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPointerCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasCapture(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasCapture());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerPosition(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().PointerPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerCursor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreCursor>(this->shim().PointerCursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerCursor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerCursor(*reinterpret_cast<winrt::Windows::UI::Core::CoreCursor const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PointerCaptureLost(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerCaptureLost(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerCaptureLost(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerCaptureLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerEntered(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerEntered(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerExited(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerExited(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerMoved(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerMoved(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerReleased(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerReleased(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerWheelChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerWheelChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerWheelChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerWheelChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICorePointerInputSource2> : produce_base<D, winrt::Windows::UI::Core::ICorePointerInputSource2>
    {
        int32_t __stdcall get_DispatcherQueue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICorePointerRedirector> : produce_base<D, winrt::Windows::UI::Core::ICorePointerRedirector>
    {
        int32_t __stdcall add_PointerRoutedAway(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerRoutedAway(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerRoutedAway(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerRoutedAway(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerRoutedTo(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerRoutedTo(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerRoutedTo(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerRoutedTo(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerRoutedReleased(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerRoutedReleased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::ICorePointerRedirector, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerRoutedReleased(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerRoutedReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreTouchHitTesting> : produce_base<D, winrt::Windows::UI::Core::ICoreTouchHitTesting>
    {
        int32_t __stdcall add_TouchHitTesting(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().TouchHitTesting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Foundation::IInspectable, winrt::Windows::UI::Core::TouchHitTestingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TouchHitTesting(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TouchHitTesting(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindow> : produce_base<D, winrt::Windows::UI::Core::ICoreWindow>
    {
        int32_t __stdcall get_AutomationHostProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().AutomationHostProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bounds(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().CustomProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Dispatcher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FlowDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreWindowFlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FlowDirection(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FlowDirection(*reinterpret_cast<winrt::Windows::UI::Core::CoreWindowFlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
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
        int32_t __stdcall get_PointerCursor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreCursor>(this->shim().PointerCursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PointerCursor(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerCursor(*reinterpret_cast<winrt::Windows::UI::Core::CoreCursor const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PointerPosition(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().PointerPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Visible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Activate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Activate();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAsyncKeyState(int32_t virtualKey, uint32_t* KeyState) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *KeyState = detach_from<winrt::Windows::UI::Core::CoreVirtualKeyStates>(this->shim().GetAsyncKeyState(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&virtualKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetKeyState(int32_t virtualKey, uint32_t* KeyState) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *KeyState = detach_from<winrt::Windows::UI::Core::CoreVirtualKeyStates>(this->shim().GetKeyState(*reinterpret_cast<winrt::Windows::System::VirtualKey const*>(&virtualKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReleasePointerCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReleasePointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPointerCapture() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Activated(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::WindowActivatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Activated(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Activated(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_AutomationProviderRequested(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().AutomationProviderRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::AutomationProviderRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AutomationProviderRequested(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutomationProviderRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_CharacterReceived(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().CharacterReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CharacterReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CharacterReceived(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CharacterReceived(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_InputEnabled(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().InputEnabled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::InputEnabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_InputEnabled(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InputEnabled(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_KeyDown(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyDown(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_KeyUp(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_KeyUp(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerCaptureLost(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerCaptureLost(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerCaptureLost(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerCaptureLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerEntered(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerEntered(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerExited(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerExited(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerMoved(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerMoved(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerPressed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerPressed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerReleased(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerReleased(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_TouchHitTesting(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().TouchHitTesting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::TouchHitTestingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TouchHitTesting(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TouchHitTesting(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_PointerWheelChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().PointerWheelChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PointerWheelChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerWheelChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_SizeChanged(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::WindowSizeChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SizeChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_VisibilityChanged(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().VisibilityChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::VisibilityChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_VisibilityChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().VisibilityChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindow2> : produce_base<D, winrt::Windows::UI::Core::ICoreWindow2>
    {
        int32_t __stdcall put_PointerPosition(winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PointerPosition(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindow3> : produce_base<D, winrt::Windows::UI::Core::ICoreWindow3>
    {
        int32_t __stdcall add_ClosestInteractiveBoundsRequested(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ClosestInteractiveBoundsRequested(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall GetCurrentKeyEventDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetCurrentKeyEventDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindow4> : produce_base<D, winrt::Windows::UI::Core::ICoreWindow4>
    {
        int32_t __stdcall add_ResizeStarted(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().ResizeStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ResizeStarted(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResizeStarted(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_ResizeCompleted(void* handler, winrt::event_token* pCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(pCookie);
            typename D::abi_guard guard(this->shim());
            *pCookie = detach_from<winrt::event_token>(this->shim().ResizeCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ResizeCompleted(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResizeCompleted(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindow5> : produce_base<D, winrt::Windows::UI::Core::ICoreWindow5>
    {
        int32_t __stdcall get_DispatcherQueue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActivationMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreWindowActivationMode>(this->shim().ActivationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowDialog> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowDialog>
    {
        int32_t __stdcall add_Showing(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().Showing(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Showing(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Showing(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_MaxSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().MaxSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().MinSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInteractionDelayed(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().IsInteractionDelayed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsInteractionDelayed(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsInteractionDelayed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Commands(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Popups::IUICommand>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultCommandIndex(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DefaultCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultCommandIndex(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CancelCommandIndex(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().CancelCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CancelCommandIndex(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CancelCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackButtonCommand(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Popups::UICommandInvokedHandler>(this->shim().BackButtonCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BackButtonCommand(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackButtonCommand(*reinterpret_cast<winrt::Windows::UI::Popups::UICommandInvokedHandler const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Popups::IUICommand>>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowDialogFactory> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowDialogFactory>
    {
        int32_t __stdcall CreateWithTitle(void* title, void** coreWindowDialog) noexcept final try
        {
            clear_abi(coreWindowDialog);
            typename D::abi_guard guard(this->shim());
            *coreWindowDialog = detach_from<winrt::Windows::UI::Core::CoreWindowDialog>(this->shim().CreateWithTitle(*reinterpret_cast<hstring const*>(&title)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowEventArgs> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowEventArgs>
    {
        int32_t __stdcall get_Handled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Handled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowFlyout> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowFlyout>
    {
        int32_t __stdcall add_Showing(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().Showing(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Core::CoreWindow, winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Showing(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Showing(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall get_MaxSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().MaxSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().MinSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsInteractionDelayed(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().IsInteractionDelayed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsInteractionDelayed(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsInteractionDelayed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Commands(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Popups::IUICommand>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultCommandIndex(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().DefaultCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DefaultCommandIndex(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackButtonCommand(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Popups::UICommandInvokedHandler>(this->shim().BackButtonCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BackButtonCommand(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackButtonCommand(*reinterpret_cast<winrt::Windows::UI::Popups::UICommandInvokedHandler const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Popups::IUICommand>>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowFlyoutFactory> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowFlyoutFactory>
    {
        int32_t __stdcall Create(winrt::Windows::Foundation::Point position, void** coreWindowFlyout) noexcept final try
        {
            clear_abi(coreWindowFlyout);
            typename D::abi_guard guard(this->shim());
            *coreWindowFlyout = detach_from<winrt::Windows::UI::Core::CoreWindowFlyout>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&position)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTitle(winrt::Windows::Foundation::Point position, void* title, void** coreWindowFlyout) noexcept final try
        {
            clear_abi(coreWindowFlyout);
            typename D::abi_guard guard(this->shim());
            *coreWindowFlyout = detach_from<winrt::Windows::UI::Core::CoreWindowFlyout>(this->shim().CreateWithTitle(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&position), *reinterpret_cast<hstring const*>(&title)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowPopupShowingEventArgs> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowPopupShowingEventArgs>
    {
        int32_t __stdcall SetDesiredSize(winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDesiredSize(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowResizeManager> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowResizeManager>
    {
        int32_t __stdcall NotifyLayoutCompleted() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyLayoutCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability>
    {
        int32_t __stdcall put_ShouldWaitForLayoutCompletion(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShouldWaitForLayoutCompletion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShouldWaitForLayoutCompletion(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShouldWaitForLayoutCompletion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowResizeManagerStatics> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowResizeManagerStatics>
    {
        int32_t __stdcall GetForCurrentView(void** CoreWindowResizeManager) noexcept final try
        {
            clear_abi(CoreWindowResizeManager);
            typename D::abi_guard guard(this->shim());
            *CoreWindowResizeManager = detach_from<winrt::Windows::UI::Core::CoreWindowResizeManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowStatic> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowStatic>
    {
        int32_t __stdcall GetForCurrentThread(void** ppWindow) noexcept final try
        {
            clear_abi(ppWindow);
            typename D::abi_guard guard(this->shim());
            *ppWindow = detach_from<winrt::Windows::UI::Core::CoreWindow>(this->shim().GetForCurrentThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ICoreWindowWithContext> : produce_base<D, winrt::Windows::UI::Core::ICoreWindowWithContext>
    {
        int32_t __stdcall get_UIContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IIdleDispatchedHandlerArgs> : produce_base<D, winrt::Windows::UI::Core::IIdleDispatchedHandlerArgs>
    {
        int32_t __stdcall get_IsDispatcherIdle(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDispatcherIdle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IInitializeWithCoreWindow> : produce_base<D, winrt::Windows::UI::Core::IInitializeWithCoreWindow>
    {
        int32_t __stdcall Initialize(void* window) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Initialize(*reinterpret_cast<winrt::Windows::UI::Core::CoreWindow const*>(&window));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IInputEnabledEventArgs> : produce_base<D, winrt::Windows::UI::Core::IInputEnabledEventArgs>
    {
        int32_t __stdcall get_InputEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().InputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IKeyEventArgs> : produce_base<D, winrt::Windows::UI::Core::IKeyEventArgs>
    {
        int32_t __stdcall get_VirtualKey(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKey>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IKeyEventArgs2> : produce_base<D, winrt::Windows::UI::Core::IKeyEventArgs2>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IPointerEventArgs> : produce_base<D, winrt::Windows::UI::Core::IPointerEventArgs>
    {
        int32_t __stdcall get_CurrentPoint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::PointerPoint>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyModifiers(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::VirtualKeyModifiers>(this->shim().KeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIntermediatePoints(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ISystemNavigationManager> : produce_base<D, winrt::Windows::UI::Core::ISystemNavigationManager>
    {
        int32_t __stdcall add_BackRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().BackRequested(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::UI::Core::BackRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_BackRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BackRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ISystemNavigationManager2> : produce_base<D, winrt::Windows::UI::Core::ISystemNavigationManager2>
    {
        int32_t __stdcall get_AppViewBackButtonVisibility(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::AppViewBackButtonVisibility>(this->shim().AppViewBackButtonVisibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppViewBackButtonVisibility(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppViewBackButtonVisibility(*reinterpret_cast<winrt::Windows::UI::Core::AppViewBackButtonVisibility const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ISystemNavigationManagerStatics> : produce_base<D, winrt::Windows::UI::Core::ISystemNavigationManagerStatics>
    {
        int32_t __stdcall GetForCurrentView(void** loader) noexcept final try
        {
            clear_abi(loader);
            typename D::abi_guard guard(this->shim());
            *loader = detach_from<winrt::Windows::UI::Core::SystemNavigationManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::ITouchHitTestingEventArgs> : produce_base<D, winrt::Windows::UI::Core::ITouchHitTestingEventArgs>
    {
        int32_t __stdcall get_ProximityEvaluation(struct struct_Windows_UI_Core_CoreProximityEvaluation* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Core::CoreProximityEvaluation>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreProximityEvaluation>(this->shim().ProximityEvaluation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProximityEvaluation(struct struct_Windows_UI_Core_CoreProximityEvaluation value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProximityEvaluation(*reinterpret_cast<winrt::Windows::UI::Core::CoreProximityEvaluation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Point(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Point());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BoundingBox(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EvaluateProximityToRect(winrt::Windows::Foundation::Rect controlBoundingBox, struct struct_Windows_UI_Core_CoreProximityEvaluation* proximityEvaluation) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Core::CoreProximityEvaluation>(proximityEvaluation);
            typename D::abi_guard guard(this->shim());
            *proximityEvaluation = detach_from<winrt::Windows::UI::Core::CoreProximityEvaluation>(this->shim().EvaluateProximity(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&controlBoundingBox)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EvaluateProximityToPolygon(uint32_t __controlVerticesSize, winrt::Windows::Foundation::Point* controlVertices, struct struct_Windows_UI_Core_CoreProximityEvaluation* proximityEvaluation) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Core::CoreProximityEvaluation>(proximityEvaluation);
            typename D::abi_guard guard(this->shim());
            *proximityEvaluation = detach_from<winrt::Windows::UI::Core::CoreProximityEvaluation>(this->shim().EvaluateProximity(array_view<winrt::Windows::Foundation::Point const>(reinterpret_cast<winrt::Windows::Foundation::Point const *>(controlVertices), reinterpret_cast<winrt::Windows::Foundation::Point const *>(controlVertices) + __controlVerticesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IVisibilityChangedEventArgs> : produce_base<D, winrt::Windows::UI::Core::IVisibilityChangedEventArgs>
    {
        int32_t __stdcall get_Visible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IWindowActivatedEventArgs> : produce_base<D, winrt::Windows::UI::Core::IWindowActivatedEventArgs>
    {
        int32_t __stdcall get_WindowActivationState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreWindowActivationState>(this->shim().WindowActivationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::IWindowSizeChangedEventArgs> : produce_base<D, winrt::Windows::UI::Core::IWindowSizeChangedEventArgs>
    {
        int32_t __stdcall get_Size(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    constexpr auto operator|(CoreIndependentInputFilters const left, CoreIndependentInputFilters const right) noexcept
    {
        return static_cast<CoreIndependentInputFilters>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(CoreIndependentInputFilters& left, CoreIndependentInputFilters const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(CoreIndependentInputFilters const left, CoreIndependentInputFilters const right) noexcept
    {
        return static_cast<CoreIndependentInputFilters>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(CoreIndependentInputFilters& left, CoreIndependentInputFilters const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(CoreIndependentInputFilters const value) noexcept
    {
        return static_cast<CoreIndependentInputFilters>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(CoreIndependentInputFilters const left, CoreIndependentInputFilters const right) noexcept
    {
        return static_cast<CoreIndependentInputFilters>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(CoreIndependentInputFilters& left, CoreIndependentInputFilters const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(CoreInputDeviceTypes const left, CoreInputDeviceTypes const right) noexcept
    {
        return static_cast<CoreInputDeviceTypes>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(CoreInputDeviceTypes& left, CoreInputDeviceTypes const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(CoreInputDeviceTypes const left, CoreInputDeviceTypes const right) noexcept
    {
        return static_cast<CoreInputDeviceTypes>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(CoreInputDeviceTypes& left, CoreInputDeviceTypes const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(CoreInputDeviceTypes const value) noexcept
    {
        return static_cast<CoreInputDeviceTypes>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(CoreInputDeviceTypes const left, CoreInputDeviceTypes const right) noexcept
    {
        return static_cast<CoreInputDeviceTypes>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(CoreInputDeviceTypes& left, CoreInputDeviceTypes const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    constexpr auto operator|(CoreVirtualKeyStates const left, CoreVirtualKeyStates const right) noexcept
    {
        return static_cast<CoreVirtualKeyStates>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(CoreVirtualKeyStates& left, CoreVirtualKeyStates const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(CoreVirtualKeyStates const left, CoreVirtualKeyStates const right) noexcept
    {
        return static_cast<CoreVirtualKeyStates>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(CoreVirtualKeyStates& left, CoreVirtualKeyStates const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(CoreVirtualKeyStates const value) noexcept
    {
        return static_cast<CoreVirtualKeyStates>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(CoreVirtualKeyStates const left, CoreVirtualKeyStates const right) noexcept
    {
        return static_cast<CoreVirtualKeyStates>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(CoreVirtualKeyStates& left, CoreVirtualKeyStates const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline CoreCursor::CoreCursor(winrt::Windows::UI::Core::CoreCursorType const& type, uint32_t id) :
        CoreCursor(impl::call_factory<CoreCursor, ICoreCursorFactory>([&](ICoreCursorFactory const& f) { return f.CreateCursor(type, id); }))
    {
    }
    inline auto CoreIndependentInputSourceController::CreateForVisual(winrt::Windows::UI::Composition::Visual const& visual)
    {
        return impl::call_factory<CoreIndependentInputSourceController, ICoreIndependentInputSourceControllerStatics>([&](ICoreIndependentInputSourceControllerStatics const& f) { return f.CreateForVisual(visual); });
    }
    inline auto CoreIndependentInputSourceController::CreateForIVisualElement(winrt::Windows::UI::Composition::IVisualElement const& visualElement)
    {
        return impl::call_factory<CoreIndependentInputSourceController, ICoreIndependentInputSourceControllerStatics>([&](ICoreIndependentInputSourceControllerStatics const& f) { return f.CreateForIVisualElement(visualElement); });
    }
    inline auto CoreWindow::GetForCurrentThread()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Core::CoreWindow(*)(ICoreWindowStatic const&), CoreWindow, ICoreWindowStatic>([](ICoreWindowStatic const& f) { return f.GetForCurrentThread(); });
    }
    inline CoreWindowDialog::CoreWindowDialog() :
        CoreWindowDialog(impl::call_factory_cast<CoreWindowDialog(*)(winrt::Windows::Foundation::IActivationFactory const&), CoreWindowDialog>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CoreWindowDialog>(); }))
    {
    }
    inline CoreWindowDialog::CoreWindowDialog(param::hstring const& title) :
        CoreWindowDialog(impl::call_factory<CoreWindowDialog, ICoreWindowDialogFactory>([&](ICoreWindowDialogFactory const& f) { return f.CreateWithTitle(title); }))
    {
    }
    inline CoreWindowFlyout::CoreWindowFlyout(winrt::Windows::Foundation::Point const& position) :
        CoreWindowFlyout(impl::call_factory<CoreWindowFlyout, ICoreWindowFlyoutFactory>([&](ICoreWindowFlyoutFactory const& f) { return f.Create(position); }))
    {
    }
    inline CoreWindowFlyout::CoreWindowFlyout(winrt::Windows::Foundation::Point const& position, param::hstring const& title) :
        CoreWindowFlyout(impl::call_factory<CoreWindowFlyout, ICoreWindowFlyoutFactory>([&](ICoreWindowFlyoutFactory const& f) { return f.CreateWithTitle(position, title); }))
    {
    }
    inline auto CoreWindowResizeManager::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Core::CoreWindowResizeManager(*)(ICoreWindowResizeManagerStatics const&), CoreWindowResizeManager, ICoreWindowResizeManagerStatics>([](ICoreWindowResizeManagerStatics const& f) { return f.GetForCurrentView(); });
    }
    inline auto SystemNavigationManager::GetForCurrentView()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Core::SystemNavigationManager(*)(ISystemNavigationManagerStatics const&), SystemNavigationManager, ISystemNavigationManagerStatics>([](ISystemNavigationManagerStatics const& f) { return f.GetForCurrentView(); });
    }
    template <typename L> DispatchedHandler::DispatchedHandler(L handler) :
        DispatchedHandler(impl::make_delegate<DispatchedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DispatchedHandler::DispatchedHandler(F* handler) :
        DispatchedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DispatchedHandler::DispatchedHandler(O* object, M method) :
        DispatchedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DispatchedHandler::DispatchedHandler(com_ptr<O>&& object, M method) :
        DispatchedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DispatchedHandler::DispatchedHandler(weak_ref<O>&& object, M method) :
        DispatchedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DispatchedHandler::operator()() const
    {
        check_hresult((*(impl::abi_t<DispatchedHandler>**)this)->Invoke());
    }
    template <typename L> IdleDispatchedHandler::IdleDispatchedHandler(L handler) :
        IdleDispatchedHandler(impl::make_delegate<IdleDispatchedHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> IdleDispatchedHandler::IdleDispatchedHandler(F* handler) :
        IdleDispatchedHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> IdleDispatchedHandler::IdleDispatchedHandler(O* object, M method) :
        IdleDispatchedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> IdleDispatchedHandler::IdleDispatchedHandler(com_ptr<O>&& object, M method) :
        IdleDispatchedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> IdleDispatchedHandler::IdleDispatchedHandler(weak_ref<O>&& object, M method) :
        IdleDispatchedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto IdleDispatchedHandler::operator()(winrt::Windows::UI::Core::IdleDispatchedHandlerArgs const& e) const
    {
        check_hresult((*(impl::abi_t<IdleDispatchedHandler>**)this)->Invoke(*(void**)(&e)));
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IBackRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICharacterReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreAcceleratorKeys> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreClosestInteractiveBoundsRequested> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreComponentFocusable> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreCursor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreCursorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreDispatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreDispatcher2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreIndependentInputSourceController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreIndependentInputSourceControllerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreInputSourceBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreKeyboardInputSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreKeyboardInputSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICorePointerInputSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICorePointerInputSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICorePointerRedirector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreTouchHitTesting> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindow2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindow3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindow4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindow5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowDialog> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowDialogFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowFlyout> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowFlyoutFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowPopupShowingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowResizeManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowResizeManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowStatic> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ICoreWindowWithContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IIdleDispatchedHandlerArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IInitializeWithCoreWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IInputEnabledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IKeyEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IKeyEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IPointerEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ISystemNavigationManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ISystemNavigationManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ISystemNavigationManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ITouchHitTestingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IVisibilityChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IWindowActivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IWindowSizeChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AcceleratorKeyEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AutomationProviderRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::BackRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CharacterReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreAcceleratorKeys> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreComponentInputSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreCursor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreDispatcher> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreIndependentInputSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreIndependentInputSourceController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreWindowDialog> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreWindowEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreWindowFlyout> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::CoreWindowResizeManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::IdleDispatchedHandlerArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::InputEnabledEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::KeyEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::PointerEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::SystemNavigationManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::TouchHitTestingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::VisibilityChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::WindowActivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::WindowSizeChangedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}

WINRT_EXPORT namespace winrt
{
    [[nodiscard]] inline auto resume_foreground(
        Windows::UI::Core::CoreDispatcher const& dispatcher,
        Windows::UI::Core::CoreDispatcherPriority const priority = Windows::UI::Core::CoreDispatcherPriority::Normal) noexcept
    {
        struct awaitable
        {
            awaitable(Windows::UI::Core::CoreDispatcher const& dispatcher, Windows::UI::Core::CoreDispatcherPriority const priority) noexcept :
                m_dispatcher(dispatcher),
                m_priority(priority)
            {
            }

            bool await_ready() const noexcept
            {
                return false;
            }

            void await_resume() const noexcept
            {
            }

            void await_suspend(impl::coroutine_handle<> handle) const
            {
                m_dispatcher.RunAsync(m_priority, [handle]
                    {
                        handle();
                    });
            }

        private:

            Windows::UI::Core::CoreDispatcher const& m_dispatcher;
            Windows::UI::Core::CoreDispatcherPriority const m_priority;
        };

        return awaitable{ dispatcher, priority };
    };

#ifdef WINRT_IMPL_COROUTINES
    inline auto operator co_await(Windows::UI::Core::CoreDispatcher const& dispatcher)
    {
        return resume_foreground(dispatcher);
    }
#endif
}
#endif
