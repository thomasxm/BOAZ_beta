// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Automation_Peers_H
#define WINRT_Windows_UI_Xaml_Automation_Peers_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.Automation.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Provider.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Peers.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAppBarAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::AppBar const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAppBarButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::AppBarButton const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAppBarToggleButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::AppBarToggleButton const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutoSuggestBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::AutoSuggestBox const& owner) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::EventsSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->get_EventsSource(&value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::EventsSource(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->put_EventsSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetPattern(winrt::Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetPattern(static_cast<int32_t>(patternInterface), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::RaiseAutomationEvent(winrt::Windows::UI::Xaml::Automation::Peers::AutomationEvents const& eventId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->RaiseAutomationEvent(static_cast<int32_t>(eventId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::RaisePropertyChangedEvent(winrt::Windows::UI::Xaml::Automation::AutomationProperty const& automationProperty, winrt::Windows::Foundation::IInspectable const& oldValue, winrt::Windows::Foundation::IInspectable const& newValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->RaisePropertyChangedEvent(*(void**)(&automationProperty), *(void**)(&oldValue), *(void**)(&newValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAcceleratorKey() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAcceleratorKey(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAccessKey() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAccessKey(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationControlType) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAutomationControlType() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationControlType result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAutomationControlType(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAutomationId() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAutomationId(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetBoundingRectangle() const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetBoundingRectangle(put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetChildren() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetChildren(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetClassName() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetClassName(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetClickablePoint() const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetClickablePoint(put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetHelpText() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetHelpText(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetItemStatus() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetItemStatus(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetItemType() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetItemType(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetLabeledBy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetLabeledBy(&result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetLocalizedControlType() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetLocalizedControlType(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetName() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetName(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationOrientation) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetOrientation() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationOrientation result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetOrientation(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::HasKeyboardFocus() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->HasKeyboardFocus(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsContentElement() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsContentElement(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsControlElement() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsControlElement(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsEnabled() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsEnabled(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsKeyboardFocusable() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsKeyboardFocusable(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsOffscreen() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsOffscreen(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsPassword() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsPassword(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsRequiredForForm() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsRequiredForForm(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::SetFocus() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->SetFocus());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetParent() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetParent(&result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::InvalidatePeer() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->InvalidatePeer());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetPeerFromPoint(winrt::Windows::Foundation::Point const& point) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetPeerFromPoint(impl::bind_in(point), &result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetLiveSetting() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetLiveSetting(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::Navigate(winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->Navigate(static_cast<int32_t>(direction), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetElementFromPoint(winrt::Windows::Foundation::Point const& pointInWindowCoordinates) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetElementFromPoint(impl::bind_in(pointInWindowCoordinates), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetFocusedElement() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetFocusedElement(&result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::ShowContextMenu() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->ShowContextMenu());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetControlledPeers() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetControlledPeers(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetAnnotations() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetAnnotations(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::SetParent(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->SetParent(*(void**)(&peer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::RaiseTextEditTextChangedEvent(winrt::Windows::UI::Xaml::Automation::AutomationTextEditChangeType const& automationTextEditChangeType, param::vector_view<hstring> const& changedData) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->RaiseTextEditTextChangedEvent(static_cast<int32_t>(automationTextEditChangeType), *(void**)(&changedData)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetPositionInSet() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetPositionInSet(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetSizeOfSet() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetSizeOfSet(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetLevel() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetLevel(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::RaiseStructureChangedEvent(winrt::Windows::UI::Xaml::Automation::Peers::AutomationStructureChangeType const& structureChangeType, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const& child) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->RaiseStructureChangedEvent(static_cast<int32_t>(structureChangeType), *(void**)(&child)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer4<D>::GetLandmarkType() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4)->GetLandmarkType(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer4<D>::GetLocalizedLandmarkType() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4)->GetLocalizedLandmarkType(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer5<D>::IsPeripheral() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5)->IsPeripheral(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer5<D>::IsDataValidForForm() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5)->IsDataValidForForm(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer5<D>::GetFullDescription() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5)->GetFullDescription(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer6<D>::GetCulture() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6)->GetCulture(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer7<D>::RaiseNotificationEvent(winrt::Windows::UI::Xaml::Automation::Peers::AutomationNotificationKind const& notificationKind, winrt::Windows::UI::Xaml::Automation::Peers::AutomationNotificationProcessing const& notificationProcessing, param::hstring const& displayString, param::hstring const& activityId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7)->RaiseNotificationEvent(static_cast<int32_t>(notificationKind), static_cast<int32_t>(notificationProcessing), *(void**)(&displayString), *(void**)(&activityId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer8<D>::GetHeadingLevel() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8)->GetHeadingLevel(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer9<D>::IsDialog() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9)->IsDialog(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::AnnotationType) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Type() const
    {
        winrt::Windows::UI::Xaml::Automation::AnnotationType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Type(winrt::Windows::UI::Xaml::Automation::AnnotationType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->put_Type(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Peer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->get_Peer(&value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Peer(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->put_Peer(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::Automation::AnnotationType const& type) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory)->CreateInstance(static_cast<int32_t>(type), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationFactory<D>::CreateWithPeerParameter(winrt::Windows::UI::Xaml::Automation::AnnotationType const& type, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory)->CreateWithPeerParameter(static_cast<int32_t>(type), *(void**)(&peer), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationStatics<D>::TypeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics)->get_TypeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationStatics<D>::PeerProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics)->get_PeerProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetPatternCore(winrt::Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetPatternCore(static_cast<int32_t>(patternInterface), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAcceleratorKeyCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAcceleratorKeyCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAccessKeyCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAccessKeyCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationControlType) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAutomationControlTypeCore() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationControlType result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAutomationControlTypeCore(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAutomationIdCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAutomationIdCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetBoundingRectangleCore() const
    {
        winrt::Windows::Foundation::Rect result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetBoundingRectangleCore(put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetChildrenCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetChildrenCore(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetClassNameCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetClassNameCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetClickablePointCore() const
    {
        winrt::Windows::Foundation::Point result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetClickablePointCore(put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetHelpTextCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetHelpTextCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetItemStatusCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetItemStatusCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetItemTypeCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetItemTypeCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetLabeledByCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetLabeledByCore(&result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetLocalizedControlTypeCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetLocalizedControlTypeCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetNameCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetNameCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationOrientation) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetOrientationCore() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationOrientation result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetOrientationCore(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::HasKeyboardFocusCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->HasKeyboardFocusCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsContentElementCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsContentElementCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsControlElementCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsControlElementCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsEnabledCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsEnabledCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsKeyboardFocusableCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsKeyboardFocusableCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsOffscreenCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsOffscreenCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsPasswordCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsPasswordCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsRequiredForFormCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsRequiredForFormCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::SetFocusCore() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->SetFocusCore());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetPeerFromPointCore(winrt::Windows::Foundation::Point const& point) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetPeerFromPointCore(impl::bind_in(point), &result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetLiveSettingCore() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetLiveSettingCore(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides2<D>::ShowContextMenuCore() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2)->ShowContextMenuCore());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides2<D>::GetControlledPeersCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2)->GetControlledPeersCore(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::NavigateCore(winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->NavigateCore(static_cast<int32_t>(direction), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetElementFromPointCore(winrt::Windows::Foundation::Point const& pointInWindowCoordinates) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetElementFromPointCore(impl::bind_in(pointInWindowCoordinates), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetFocusedElementCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetFocusedElementCore(&result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetAnnotationsCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetAnnotationsCore(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetPositionInSetCore() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetPositionInSetCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetSizeOfSetCore() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetSizeOfSetCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetLevelCore() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetLevelCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides4<D>::GetLandmarkTypeCore() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4)->GetLandmarkTypeCore(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides4<D>::GetLocalizedLandmarkTypeCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4)->GetLocalizedLandmarkTypeCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::IsPeripheralCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->IsPeripheralCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::IsDataValidForFormCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->IsDataValidForFormCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetFullDescriptionCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetFullDescriptionCore(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetDescribedByCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetDescribedByCore(&result));
        return winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetFlowsToCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetFlowsToCore(&result));
        return winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetFlowsFromCore() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetFlowsFromCore(&result));
        return winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides6<D>::GetCultureCore() const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6)->GetCultureCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides8<D>::GetHeadingLevelCore() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8)->GetHeadingLevelCore(reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides9<D>::IsDialogCore() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9)->IsDialogCore(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerProtected<D>::PeerFromProvider(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& provider) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected)->PeerFromProvider(*(void**)(&provider), &result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerProtected<D>::ProviderFromPeer(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected)->ProviderFromPeer(*(void**)(&peer), &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerStatics<D>::ListenerExists(winrt::Windows::UI::Xaml::Automation::Peers::AutomationEvents const& eventId) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics)->ListenerExists(static_cast<int32_t>(eventId), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId) consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerStatics3<D>::GenerateRawElementProviderRuntimeId() const
    {
        winrt::Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3)->GenerateRawElementProviderRuntimeId(put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Button const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IButtonBaseAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ICalendarDatePickerAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::CalendarDatePicker const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ICaptureElementAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::CaptureElement const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ICheckBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::CheckBox const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IColorPickerSliderAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IColorSpectrumAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IComboBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ComboBox const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IComboBoxItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ComboBoxItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IComboBoxItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const& parent, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IDatePickerAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::DatePicker const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IFlipViewAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::FlipView const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IFlipViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::FlipViewItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IFlipViewItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const& parent, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IFlyoutPresenterAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::FlyoutPresenter const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeer<D>::Owner() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer)->get_Owner(&value));
        return winrt::Windows::UI::Xaml::UIElement{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::FrameworkElement const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeerStatics<D>::FromElement(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics)->FromElement(*(void**)(&element), &result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeerStatics<D>::CreatePeerForElement(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics)->CreatePeerForElement(*(void**)(&element), &result));
        return winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IGridViewAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::GridView const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IGridViewHeaderItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::GridViewHeaderItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IGridViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::GridViewItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IGridViewItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const& parent, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IGroupItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::GroupItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::HubAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IHubAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Hub const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::HubAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IHubSectionAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::HubSection const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IHyperlinkButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::HyperlinkButton const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IImageAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Image const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Peers_IItemAutomationPeer<D>::Item() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer)->get_Item(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IItemAutomationPeer<D>::ItemsControlAutomationPeer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer)->get_ItemsControlAutomationPeer(&value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IItemAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const& parent, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IItemsControlAutomationPeer2<D>::CreateItemAutomationPeer(winrt::Windows::Foundation::IInspectable const& item) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2)->CreateItemAutomationPeer(*(void**)(&item), &result));
        return winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IItemsControlAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ItemsControl const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IItemsControlAutomationPeerOverrides2<D>::OnCreateItemAutomationPeer(winrt::Windows::Foundation::IInspectable const& item) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2)->OnCreateItemAutomationPeer(*(void**)(&item), &result));
        return winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ListBox const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListBoxItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ListBoxItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListBoxItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const& parent, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListViewAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ListView const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListViewBaseAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ListViewBase const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListViewBaseHeaderItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ListViewBaseHeaderItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListViewHeaderItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ListViewHeaderItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ListViewItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IListViewItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const& parent, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IMediaElementAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::MediaElement const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IMediaPlayerElementAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::MediaPlayerElement const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IMediaTransportControlsAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::MediaTransportControls const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IMenuBarAutomationPeerFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::Controls::MenuBar const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory)->CreateInstance(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IMenuBarItemAutomationPeerFactory<D>::CreateInstance(winrt::Windows::UI::Xaml::Controls::MenuBarItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory)->CreateInstance(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IMenuFlyoutItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::MenuFlyoutItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IMenuFlyoutPresenterAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::MenuFlyoutPresenter const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_INavigationViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::NavigationViewItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IPasswordBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::PasswordBox const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IPersonPictureAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::PersonPicture const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IPivotAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Pivot const& owner) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IPivotItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::PivotItem const& owner) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IPivotItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer const& parent) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IProgressBarAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ProgressBar const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IProgressRingAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ProgressRing const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IRadioButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::RadioButton const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IRangeBaseAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IRatingControlAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::RatingControl const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IRepeatButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::RepeatButton const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IRichEditBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::RichEditBox const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IRichTextBlockAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::RichTextBlock const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IRichTextBlockOverflowAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::RichTextBlockOverflow const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IScrollBarAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::ScrollBar const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IScrollViewerAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ScrollViewer const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ISearchBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::SearchBox const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ISelectorAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::Selector const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ISelectorItemAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const& parent, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory)->CreateInstanceWithParentAndItem(*(void**)(&item), *(void**)(&parent), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ISemanticZoomAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::SemanticZoom const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ISettingsFlyoutAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::SettingsFlyout const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ISliderAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Slider const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ITextBlockAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::TextBlock const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ITextBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::TextBox const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IThumbAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::Thumb const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ITimePickerAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::TimePicker const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IToggleButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IToggleMenuFlyoutItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_IToggleSwitchAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::ToggleSwitch const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ITreeViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::TreeViewItem const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer) consume_Windows_UI_Xaml_Automation_Peers_ITreeViewListAutomationPeerFactory<D>::CreateInstanceWithOwner(winrt::Windows::UI::Xaml::Controls::TreeViewList const& owner, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory)->CreateInstanceWithOwner(*(void**)(&owner), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::AppBar const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::AppBarButton const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::AppBarToggleButton const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::AutoSuggestBox const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer>
    {
        int32_t __stdcall get_EventsSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().EventsSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EventsSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EventsSource(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPattern(int32_t patternInterface, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetPattern(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::PatternInterface const*>(&patternInterface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RaiseAutomationEvent(int32_t eventId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RaiseAutomationEvent(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationEvents const*>(&eventId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RaisePropertyChangedEvent(void* automationProperty, void* oldValue, void* newValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RaisePropertyChangedEvent(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::AutomationProperty const*>(&automationProperty), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&oldValue), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&newValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAcceleratorKey(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetAcceleratorKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAccessKey(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetAccessKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAutomationControlType(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationControlType>(this->shim().GetAutomationControlType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAutomationId(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetAutomationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBoundingRectangle(winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().GetBoundingRectangle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetChildren(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetChildren());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetClassName(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetClassName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetClickablePoint(winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetClickablePoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHelpText(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetHelpText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemStatus(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetItemStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemType(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetItemType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLabeledBy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetLabeledBy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLocalizedControlType(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetLocalizedControlType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetName(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOrientation(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationOrientation>(this->shim().GetOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HasKeyboardFocus(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().HasKeyboardFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsContentElement(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsContentElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsControlElement(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsControlElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsEnabled(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsKeyboardFocusable(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsKeyboardFocusable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsOffscreen(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsOffscreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsPassword(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPassword());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsRequiredForForm(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsRequiredForForm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFocus() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFocus();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetParent(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetParent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InvalidatePeer() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InvalidatePeer();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPeerFromPoint(winrt::Windows::Foundation::Point point, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetPeerFromPoint(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLiveSetting(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting>(this->shim().GetLiveSetting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3>
    {
        int32_t __stdcall Navigate(int32_t direction, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Navigate(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetElementFromPoint(winrt::Windows::Foundation::Point pointInWindowCoordinates, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetElementFromPoint(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&pointInWindowCoordinates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFocusedElement(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowContextMenu() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowContextMenu();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetControlledPeers(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetControlledPeers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnnotations(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>>(this->shim().GetAnnotations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetParent(void* peer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetParent(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&peer));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RaiseTextEditTextChangedEvent(int32_t automationTextEditChangeType, void* changedData) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RaiseTextEditTextChangedEvent(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::AutomationTextEditChangeType const*>(&automationTextEditChangeType), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring> const*>(&changedData));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPositionInSet(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetPositionInSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSizeOfSet(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetSizeOfSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLevel(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RaiseStructureChangedEvent(int32_t structureChangeType, void* child) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RaiseStructureChangedEvent(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationStructureChangeType const*>(&structureChangeType), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&child));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4>
    {
        int32_t __stdcall GetLandmarkType(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType>(this->shim().GetLandmarkType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLocalizedLandmarkType(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetLocalizedLandmarkType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5>
    {
        int32_t __stdcall IsPeripheral(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPeripheral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsDataValidForForm(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsDataValidForForm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFullDescription(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetFullDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6>
    {
        int32_t __stdcall GetCulture(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetCulture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7>
    {
        int32_t __stdcall RaiseNotificationEvent(int32_t notificationKind, int32_t notificationProcessing, void* displayString, void* activityId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RaiseNotificationEvent(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationNotificationKind const*>(&notificationKind), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationNotificationProcessing const*>(&notificationProcessing), *reinterpret_cast<hstring const*>(&displayString), *reinterpret_cast<hstring const*>(&activityId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8>
    {
        int32_t __stdcall GetHeadingLevel(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel>(this->shim().GetHeadingLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9>
    {
        int32_t __stdcall IsDialog(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsDialog());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::AnnotationType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Type(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Type(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::AnnotationType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Peer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().Peer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Peer(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Peer(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory>
    {
        int32_t __stdcall CreateInstance(int32_t type, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::AnnotationType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithPeerParameter(int32_t type, void* peer, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>(this->shim().CreateWithPeerParameter(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::AnnotationType const*>(&type), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&peer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics>
    {
        int32_t __stdcall get_TypeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().TypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PeerProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PeerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides>
    {
        int32_t __stdcall GetPatternCore(int32_t patternInterface, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetPatternCore(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::PatternInterface const*>(&patternInterface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAcceleratorKeyCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetAcceleratorKeyCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAccessKeyCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetAccessKeyCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAutomationControlTypeCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationControlType>(this->shim().GetAutomationControlTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAutomationIdCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetAutomationIdCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBoundingRectangleCore(winrt::Windows::Foundation::Rect* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Rect>(this->shim().GetBoundingRectangleCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetChildrenCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetChildrenCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetClassNameCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetClassNameCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetClickablePointCore(winrt::Windows::Foundation::Point* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Point>(this->shim().GetClickablePointCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetHelpTextCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetHelpTextCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemStatusCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetItemStatusCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItemTypeCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetItemTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLabeledByCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetLabeledByCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLocalizedControlTypeCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetLocalizedControlTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNameCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetNameCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOrientationCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationOrientation>(this->shim().GetOrientationCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HasKeyboardFocusCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().HasKeyboardFocusCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsContentElementCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsContentElementCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsControlElementCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsControlElementCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsEnabledCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsEnabledCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsKeyboardFocusableCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsKeyboardFocusableCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsOffscreenCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsOffscreenCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsPasswordCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPasswordCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsRequiredForFormCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsRequiredForFormCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFocusCore() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFocusCore();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPeerFromPointCore(winrt::Windows::Foundation::Point point, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetPeerFromPointCore(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLiveSettingCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting>(this->shim().GetLiveSettingCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2>
    {
        int32_t __stdcall ShowContextMenuCore() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowContextMenuCore();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetControlledPeersCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetControlledPeersCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3>
    {
        int32_t __stdcall NavigateCore(int32_t direction, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().NavigateCore(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetElementFromPointCore(winrt::Windows::Foundation::Point pointInWindowCoordinates, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetElementFromPointCore(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&pointInWindowCoordinates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFocusedElementCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetFocusedElementCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnnotationsCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>>(this->shim().GetAnnotationsCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPositionInSetCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetPositionInSetCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSizeOfSetCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetSizeOfSetCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLevelCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetLevelCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4>
    {
        int32_t __stdcall GetLandmarkTypeCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType>(this->shim().GetLandmarkTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetLocalizedLandmarkTypeCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetLocalizedLandmarkTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5>
    {
        int32_t __stdcall IsPeripheralCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPeripheralCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsDataValidForFormCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsDataValidForFormCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFullDescriptionCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetFullDescriptionCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDescribedByCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetDescribedByCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFlowsToCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetFlowsToCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFlowsFromCore(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetFlowsFromCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6>
    {
        int32_t __stdcall GetCultureCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().GetCultureCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8>
    {
        int32_t __stdcall GetHeadingLevelCore(int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel>(this->shim().GetHeadingLevelCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9>
    {
        int32_t __stdcall IsDialogCore(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsDialogCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected>
    {
        int32_t __stdcall PeerFromProvider(void* provider, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().PeerFromProvider(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProviderFromPeer(void* peer, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().ProviderFromPeer(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&peer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics>
    {
        int32_t __stdcall ListenerExists(int32_t eventId, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().ListenerExists(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationEvents const*>(&eventId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3>
    {
        int32_t __stdcall GenerateRawElementProviderRuntimeId(struct struct_Windows_UI_Xaml_Automation_Peers_RawElementProviderRuntimeId* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId>(this->shim().GenerateRawElementProviderRuntimeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Button const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::CalendarDatePicker const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::CaptureElement const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::CheckBox const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ComboBox const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ComboBoxItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const*>(&parent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::DatePicker const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerFlyoutPresenterAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerFlyoutPresenterAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::FlipView const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::FlipViewItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const*>(&parent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::FlyoutPresenter const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer>
    {
        int32_t __stdcall get_Owner(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::UIElement>(this->shim().Owner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::FrameworkElement const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics>
    {
        int32_t __stdcall FromElement(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().FromElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePeerForElement(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().CreatePeerForElement(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::GridView const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::GridViewHeaderItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::GridViewItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const*>(&parent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::GroupItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::HubAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Hub const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::HubSection const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::HyperlinkButton const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Image const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IInkToolbarAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IInkToolbarAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer>
    {
        int32_t __stdcall get_Item(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemsControlAutomationPeer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer>(this->shim().ItemsControlAutomationPeer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const*>(&parent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2>
    {
        int32_t __stdcall CreateItemAutomationPeer(void* item, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer>(this->shim().CreateItemAutomationPeer(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ItemsControl const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2>
    {
        int32_t __stdcall OnCreateItemAutomationPeer(void* item, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer>(this->shim().OnCreateItemAutomationPeer(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListBox const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListBoxItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const*>(&parent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListPickerFlyoutPresenterAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListPickerFlyoutPresenterAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListView const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListViewBase const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListViewBaseHeaderItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListViewHeaderItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ListViewItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const*>(&parent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemDataAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemDataAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMapControlAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMapControlAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::MediaElement const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::MediaPlayerElement const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::MediaTransportControls const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstance(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::MenuBar const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstance(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::MenuBarItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::MenuFlyoutItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::MenuFlyoutPresenter const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::NavigationViewItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::PasswordBox const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::PersonPicture const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPickerFlyoutPresenterAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPickerFlyoutPresenterAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Pivot const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::PivotItem const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer const*>(&parent)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ProgressBar const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ProgressRing const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::RadioButton const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::RatingControl const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::RepeatButton const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::RichEditBox const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::RichTextBlock const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::RichTextBlockOverflow const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ScrollBar const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ScrollViewer const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::SearchBox const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::Selector const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const*>(&parent), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::SemanticZoom const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::SettingsFlyout const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Slider const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::TextBlock const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::TextBox const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::Thumb const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::TimePicker const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerFlyoutPresenterAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerFlyoutPresenterAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::ToggleSwitch const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::TreeViewItem const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory>
    {
        int32_t __stdcall CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<winrt::Windows::UI::Xaml::Controls::TreeViewList const*>(&owner), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides>
{
    auto GetPatternCore(winrt::Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetPatternCore(patternInterface);
        }

        return this->shim().GetPatternCore(patternInterface);
    }
    auto GetAcceleratorKeyCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetAcceleratorKeyCore();
        }

        return this->shim().GetAcceleratorKeyCore();
    }
    auto GetAccessKeyCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetAccessKeyCore();
        }

        return this->shim().GetAccessKeyCore();
    }
    auto GetAutomationControlTypeCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetAutomationControlTypeCore();
        }

        return this->shim().GetAutomationControlTypeCore();
    }
    auto GetAutomationIdCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetAutomationIdCore();
        }

        return this->shim().GetAutomationIdCore();
    }
    auto GetBoundingRectangleCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetBoundingRectangleCore();
        }

        return this->shim().GetBoundingRectangleCore();
    }
    auto GetChildrenCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetChildrenCore();
        }

        return this->shim().GetChildrenCore();
    }
    auto GetClassNameCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetClassNameCore();
        }

        return this->shim().GetClassNameCore();
    }
    auto GetClickablePointCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetClickablePointCore();
        }

        return this->shim().GetClickablePointCore();
    }
    auto GetHelpTextCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetHelpTextCore();
        }

        return this->shim().GetHelpTextCore();
    }
    auto GetItemStatusCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetItemStatusCore();
        }

        return this->shim().GetItemStatusCore();
    }
    auto GetItemTypeCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetItemTypeCore();
        }

        return this->shim().GetItemTypeCore();
    }
    auto GetLabeledByCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetLabeledByCore();
        }

        return this->shim().GetLabeledByCore();
    }
    auto GetLocalizedControlTypeCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetLocalizedControlTypeCore();
        }

        return this->shim().GetLocalizedControlTypeCore();
    }
    auto GetNameCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetNameCore();
        }

        return this->shim().GetNameCore();
    }
    auto GetOrientationCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetOrientationCore();
        }

        return this->shim().GetOrientationCore();
    }
    auto HasKeyboardFocusCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.HasKeyboardFocusCore();
        }

        return this->shim().HasKeyboardFocusCore();
    }
    auto IsContentElementCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsContentElementCore();
        }

        return this->shim().IsContentElementCore();
    }
    auto IsControlElementCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsControlElementCore();
        }

        return this->shim().IsControlElementCore();
    }
    auto IsEnabledCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsEnabledCore();
        }

        return this->shim().IsEnabledCore();
    }
    auto IsKeyboardFocusableCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsKeyboardFocusableCore();
        }

        return this->shim().IsKeyboardFocusableCore();
    }
    auto IsOffscreenCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsOffscreenCore();
        }

        return this->shim().IsOffscreenCore();
    }
    auto IsPasswordCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsPasswordCore();
        }

        return this->shim().IsPasswordCore();
    }
    auto IsRequiredForFormCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsRequiredForFormCore();
        }

        return this->shim().IsRequiredForFormCore();
    }
    auto SetFocusCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.SetFocusCore();
        }

        return this->shim().SetFocusCore();
    }
    auto GetPeerFromPointCore(winrt::Windows::Foundation::Point const& point)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetPeerFromPointCore(point);
        }

        return this->shim().GetPeerFromPointCore(point);
    }
    auto GetLiveSettingCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetLiveSettingCore();
        }

        return this->shim().GetLiveSettingCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2>
{
    auto ShowContextMenuCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.ShowContextMenuCore();
        }

        return this->shim().ShowContextMenuCore();
    }
    auto GetControlledPeersCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetControlledPeersCore();
        }

        return this->shim().GetControlledPeersCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3>
{
    auto NavigateCore(winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.NavigateCore(direction);
        }

        return this->shim().NavigateCore(direction);
    }
    auto GetElementFromPointCore(winrt::Windows::Foundation::Point const& pointInWindowCoordinates)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetElementFromPointCore(pointInWindowCoordinates);
        }

        return this->shim().GetElementFromPointCore(pointInWindowCoordinates);
    }
    auto GetFocusedElementCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetFocusedElementCore();
        }

        return this->shim().GetFocusedElementCore();
    }
    auto GetAnnotationsCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetAnnotationsCore();
        }

        return this->shim().GetAnnotationsCore();
    }
    auto GetPositionInSetCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetPositionInSetCore();
        }

        return this->shim().GetPositionInSetCore();
    }
    auto GetSizeOfSetCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetSizeOfSetCore();
        }

        return this->shim().GetSizeOfSetCore();
    }
    auto GetLevelCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetLevelCore();
        }

        return this->shim().GetLevelCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4>
{
    auto GetLandmarkTypeCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetLandmarkTypeCore();
        }

        return this->shim().GetLandmarkTypeCore();
    }
    auto GetLocalizedLandmarkTypeCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetLocalizedLandmarkTypeCore();
        }

        return this->shim().GetLocalizedLandmarkTypeCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5>
{
    auto IsPeripheralCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsPeripheralCore();
        }

        return this->shim().IsPeripheralCore();
    }
    auto IsDataValidForFormCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsDataValidForFormCore();
        }

        return this->shim().IsDataValidForFormCore();
    }
    auto GetFullDescriptionCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetFullDescriptionCore();
        }

        return this->shim().GetFullDescriptionCore();
    }
    auto GetDescribedByCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetDescribedByCore();
        }

        return this->shim().GetDescribedByCore();
    }
    auto GetFlowsToCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetFlowsToCore();
        }

        return this->shim().GetFlowsToCore();
    }
    auto GetFlowsFromCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetFlowsFromCore();
        }

        return this->shim().GetFlowsFromCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6>
{
    auto GetCultureCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetCultureCore();
        }

        return this->shim().GetCultureCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8>
{
    auto GetHeadingLevelCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.GetHeadingLevelCore();
        }

        return this->shim().GetHeadingLevelCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9>
{
    auto IsDialogCore()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.IsDialogCore();
        }

        return this->shim().IsDialogCore();
    }
};
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2>
{
    auto OnCreateItemAutomationPeer(winrt::Windows::Foundation::IInspectable const& item)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnCreateItemAutomationPeer(item);
        }

        return this->shim().OnCreateItemAutomationPeer(item);
    }
};
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Automation::Peers
{
    inline AppBarAutomationPeer::AppBarAutomationPeer(winrt::Windows::UI::Xaml::Controls::AppBar const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<AppBarAutomationPeer, IAppBarAutomationPeerFactory>([&](IAppBarAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline AppBarButtonAutomationPeer::AppBarButtonAutomationPeer(winrt::Windows::UI::Xaml::Controls::AppBarButton const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<AppBarButtonAutomationPeer, IAppBarButtonAutomationPeerFactory>([&](IAppBarButtonAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline AppBarToggleButtonAutomationPeer::AppBarToggleButtonAutomationPeer(winrt::Windows::UI::Xaml::Controls::AppBarToggleButton const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<AppBarToggleButtonAutomationPeer, IAppBarToggleButtonAutomationPeerFactory>([&](IAppBarToggleButtonAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline AutoSuggestBoxAutomationPeer::AutoSuggestBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::AutoSuggestBox const& owner) :
        AutoSuggestBoxAutomationPeer(impl::call_factory<AutoSuggestBoxAutomationPeer, IAutoSuggestBoxAutomationPeerFactory>([&](IAutoSuggestBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner); }))
    {
    }
    inline auto AutomationPeer::ListenerExists(winrt::Windows::UI::Xaml::Automation::Peers::AutomationEvents const& eventId)
    {
        return impl::call_factory<AutomationPeer, IAutomationPeerStatics>([&](IAutomationPeerStatics const& f) { return f.ListenerExists(eventId); });
    }
    inline auto AutomationPeer::GenerateRawElementProviderRuntimeId()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId(*)(IAutomationPeerStatics3 const&), AutomationPeer, IAutomationPeerStatics3>([](IAutomationPeerStatics3 const& f) { return f.GenerateRawElementProviderRuntimeId(); });
    }
    inline AutomationPeerAnnotation::AutomationPeerAnnotation() :
        AutomationPeerAnnotation(impl::call_factory_cast<AutomationPeerAnnotation(*)(winrt::Windows::Foundation::IActivationFactory const&), AutomationPeerAnnotation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AutomationPeerAnnotation>(); }))
    {
    }
    inline AutomationPeerAnnotation::AutomationPeerAnnotation(winrt::Windows::UI::Xaml::Automation::AnnotationType const& type) :
        AutomationPeerAnnotation(impl::call_factory<AutomationPeerAnnotation, IAutomationPeerAnnotationFactory>([&](IAutomationPeerAnnotationFactory const& f) { return f.CreateInstance(type); }))
    {
    }
    inline AutomationPeerAnnotation::AutomationPeerAnnotation(winrt::Windows::UI::Xaml::Automation::AnnotationType const& type, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) :
        AutomationPeerAnnotation(impl::call_factory<AutomationPeerAnnotation, IAutomationPeerAnnotationFactory>([&](IAutomationPeerAnnotationFactory const& f) { return f.CreateWithPeerParameter(type, peer); }))
    {
    }
    inline auto AutomationPeerAnnotation::TypeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IAutomationPeerAnnotationStatics const&), AutomationPeerAnnotation, IAutomationPeerAnnotationStatics>([](IAutomationPeerAnnotationStatics const& f) { return f.TypeProperty(); });
    }
    inline auto AutomationPeerAnnotation::PeerProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IAutomationPeerAnnotationStatics const&), AutomationPeerAnnotation, IAutomationPeerAnnotationStatics>([](IAutomationPeerAnnotationStatics const& f) { return f.PeerProperty(); });
    }
    inline ButtonAutomationPeer::ButtonAutomationPeer(winrt::Windows::UI::Xaml::Controls::Button const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ButtonAutomationPeer, IButtonAutomationPeerFactory>([&](IButtonAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline CalendarDatePickerAutomationPeer::CalendarDatePickerAutomationPeer(winrt::Windows::UI::Xaml::Controls::CalendarDatePicker const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<CalendarDatePickerAutomationPeer, ICalendarDatePickerAutomationPeerFactory>([&](ICalendarDatePickerAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline CaptureElementAutomationPeer::CaptureElementAutomationPeer(winrt::Windows::UI::Xaml::Controls::CaptureElement const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<CaptureElementAutomationPeer, ICaptureElementAutomationPeerFactory>([&](ICaptureElementAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline CheckBoxAutomationPeer::CheckBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::CheckBox const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<CheckBoxAutomationPeer, ICheckBoxAutomationPeerFactory>([&](ICheckBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ColorPickerSliderAutomationPeer::ColorPickerSliderAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ColorPickerSliderAutomationPeer, IColorPickerSliderAutomationPeerFactory>([&](IColorPickerSliderAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ColorSpectrumAutomationPeer::ColorSpectrumAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ColorSpectrumAutomationPeer, IColorSpectrumAutomationPeerFactory>([&](IColorSpectrumAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ComboBoxAutomationPeer::ComboBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::ComboBox const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ComboBoxAutomationPeer, IComboBoxAutomationPeerFactory>([&](IComboBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ComboBoxItemAutomationPeer::ComboBoxItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::ComboBoxItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ComboBoxItemAutomationPeer, IComboBoxItemAutomationPeerFactory>([&](IComboBoxItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ComboBoxItemDataAutomationPeer::ComboBoxItemDataAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const& parent)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ComboBoxItemDataAutomationPeer, IComboBoxItemDataAutomationPeerFactory>([&](IComboBoxItemDataAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
    }
    inline DatePickerAutomationPeer::DatePickerAutomationPeer(winrt::Windows::UI::Xaml::Controls::DatePicker const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<DatePickerAutomationPeer, IDatePickerAutomationPeerFactory>([&](IDatePickerAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline FlipViewAutomationPeer::FlipViewAutomationPeer(winrt::Windows::UI::Xaml::Controls::FlipView const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<FlipViewAutomationPeer, IFlipViewAutomationPeerFactory>([&](IFlipViewAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline FlipViewItemAutomationPeer::FlipViewItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::FlipViewItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<FlipViewItemAutomationPeer, IFlipViewItemAutomationPeerFactory>([&](IFlipViewItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline FlipViewItemDataAutomationPeer::FlipViewItemDataAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const& parent)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<FlipViewItemDataAutomationPeer, IFlipViewItemDataAutomationPeerFactory>([&](IFlipViewItemDataAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
    }
    inline FlyoutPresenterAutomationPeer::FlyoutPresenterAutomationPeer(winrt::Windows::UI::Xaml::Controls::FlyoutPresenter const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<FlyoutPresenterAutomationPeer, IFlyoutPresenterAutomationPeerFactory>([&](IFlyoutPresenterAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline FrameworkElementAutomationPeer::FrameworkElementAutomationPeer(winrt::Windows::UI::Xaml::FrameworkElement const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<FrameworkElementAutomationPeer, IFrameworkElementAutomationPeerFactory>([&](IFrameworkElementAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline auto FrameworkElementAutomationPeer::FromElement(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<FrameworkElementAutomationPeer, IFrameworkElementAutomationPeerStatics>([&](IFrameworkElementAutomationPeerStatics const& f) { return f.FromElement(element); });
    }
    inline auto FrameworkElementAutomationPeer::CreatePeerForElement(winrt::Windows::UI::Xaml::UIElement const& element)
    {
        return impl::call_factory<FrameworkElementAutomationPeer, IFrameworkElementAutomationPeerStatics>([&](IFrameworkElementAutomationPeerStatics const& f) { return f.CreatePeerForElement(element); });
    }
    inline GridViewAutomationPeer::GridViewAutomationPeer(winrt::Windows::UI::Xaml::Controls::GridView const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<GridViewAutomationPeer, IGridViewAutomationPeerFactory>([&](IGridViewAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline GridViewHeaderItemAutomationPeer::GridViewHeaderItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::GridViewHeaderItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<GridViewHeaderItemAutomationPeer, IGridViewHeaderItemAutomationPeerFactory>([&](IGridViewHeaderItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline GridViewItemAutomationPeer::GridViewItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::GridViewItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<GridViewItemAutomationPeer, IGridViewItemAutomationPeerFactory>([&](IGridViewItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline GridViewItemDataAutomationPeer::GridViewItemDataAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const& parent)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<GridViewItemDataAutomationPeer, IGridViewItemDataAutomationPeerFactory>([&](IGridViewItemDataAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
    }
    inline GroupItemAutomationPeer::GroupItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::GroupItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<GroupItemAutomationPeer, IGroupItemAutomationPeerFactory>([&](IGroupItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline HubAutomationPeer::HubAutomationPeer(winrt::Windows::UI::Xaml::Controls::Hub const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<HubAutomationPeer, IHubAutomationPeerFactory>([&](IHubAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline HubSectionAutomationPeer::HubSectionAutomationPeer(winrt::Windows::UI::Xaml::Controls::HubSection const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<HubSectionAutomationPeer, IHubSectionAutomationPeerFactory>([&](IHubSectionAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline HyperlinkButtonAutomationPeer::HyperlinkButtonAutomationPeer(winrt::Windows::UI::Xaml::Controls::HyperlinkButton const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<HyperlinkButtonAutomationPeer, IHyperlinkButtonAutomationPeerFactory>([&](IHyperlinkButtonAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ImageAutomationPeer::ImageAutomationPeer(winrt::Windows::UI::Xaml::Controls::Image const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ImageAutomationPeer, IImageAutomationPeerFactory>([&](IImageAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ItemAutomationPeer::ItemAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const& parent)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ItemAutomationPeer, IItemAutomationPeerFactory>([&](IItemAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
    }
    inline ItemsControlAutomationPeer::ItemsControlAutomationPeer(winrt::Windows::UI::Xaml::Controls::ItemsControl const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ItemsControlAutomationPeer, IItemsControlAutomationPeerFactory>([&](IItemsControlAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ListBoxAutomationPeer::ListBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::ListBox const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListBoxAutomationPeer, IListBoxAutomationPeerFactory>([&](IListBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ListBoxItemAutomationPeer::ListBoxItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::ListBoxItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListBoxItemAutomationPeer, IListBoxItemAutomationPeerFactory>([&](IListBoxItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ListBoxItemDataAutomationPeer::ListBoxItemDataAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const& parent)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListBoxItemDataAutomationPeer, IListBoxItemDataAutomationPeerFactory>([&](IListBoxItemDataAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
    }
    inline ListViewAutomationPeer::ListViewAutomationPeer(winrt::Windows::UI::Xaml::Controls::ListView const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListViewAutomationPeer, IListViewAutomationPeerFactory>([&](IListViewAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ListViewBaseAutomationPeer::ListViewBaseAutomationPeer(winrt::Windows::UI::Xaml::Controls::ListViewBase const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListViewBaseAutomationPeer, IListViewBaseAutomationPeerFactory>([&](IListViewBaseAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ListViewHeaderItemAutomationPeer::ListViewHeaderItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::ListViewHeaderItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListViewHeaderItemAutomationPeer, IListViewHeaderItemAutomationPeerFactory>([&](IListViewHeaderItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ListViewItemAutomationPeer::ListViewItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::ListViewItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListViewItemAutomationPeer, IListViewItemAutomationPeerFactory>([&](IListViewItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ListViewItemDataAutomationPeer::ListViewItemDataAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const& parent)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ListViewItemDataAutomationPeer, IListViewItemDataAutomationPeerFactory>([&](IListViewItemDataAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
    }
    inline MediaElementAutomationPeer::MediaElementAutomationPeer(winrt::Windows::UI::Xaml::Controls::MediaElement const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MediaElementAutomationPeer, IMediaElementAutomationPeerFactory>([&](IMediaElementAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline MediaPlayerElementAutomationPeer::MediaPlayerElementAutomationPeer(winrt::Windows::UI::Xaml::Controls::MediaPlayerElement const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MediaPlayerElementAutomationPeer, IMediaPlayerElementAutomationPeerFactory>([&](IMediaPlayerElementAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline MediaTransportControlsAutomationPeer::MediaTransportControlsAutomationPeer(winrt::Windows::UI::Xaml::Controls::MediaTransportControls const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MediaTransportControlsAutomationPeer, IMediaTransportControlsAutomationPeerFactory>([&](IMediaTransportControlsAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline MenuBarAutomationPeer::MenuBarAutomationPeer(winrt::Windows::UI::Xaml::Controls::MenuBar const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MenuBarAutomationPeer, IMenuBarAutomationPeerFactory>([&](IMenuBarAutomationPeerFactory const& f) { return f.CreateInstance(owner, baseInterface, innerInterface); });
    }
    inline MenuBarItemAutomationPeer::MenuBarItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::MenuBarItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MenuBarItemAutomationPeer, IMenuBarItemAutomationPeerFactory>([&](IMenuBarItemAutomationPeerFactory const& f) { return f.CreateInstance(owner, baseInterface, innerInterface); });
    }
    inline MenuFlyoutItemAutomationPeer::MenuFlyoutItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::MenuFlyoutItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MenuFlyoutItemAutomationPeer, IMenuFlyoutItemAutomationPeerFactory>([&](IMenuFlyoutItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline MenuFlyoutPresenterAutomationPeer::MenuFlyoutPresenterAutomationPeer(winrt::Windows::UI::Xaml::Controls::MenuFlyoutPresenter const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MenuFlyoutPresenterAutomationPeer, IMenuFlyoutPresenterAutomationPeerFactory>([&](IMenuFlyoutPresenterAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline NavigationViewItemAutomationPeer::NavigationViewItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::NavigationViewItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<NavigationViewItemAutomationPeer, INavigationViewItemAutomationPeerFactory>([&](INavigationViewItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline PasswordBoxAutomationPeer::PasswordBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::PasswordBox const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<PasswordBoxAutomationPeer, IPasswordBoxAutomationPeerFactory>([&](IPasswordBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline PersonPictureAutomationPeer::PersonPictureAutomationPeer(winrt::Windows::UI::Xaml::Controls::PersonPicture const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<PersonPictureAutomationPeer, IPersonPictureAutomationPeerFactory>([&](IPersonPictureAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline PivotAutomationPeer::PivotAutomationPeer(winrt::Windows::UI::Xaml::Controls::Pivot const& owner) :
        PivotAutomationPeer(impl::call_factory<PivotAutomationPeer, IPivotAutomationPeerFactory>([&](IPivotAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner); }))
    {
    }
    inline PivotItemAutomationPeer::PivotItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::PivotItem const& owner) :
        PivotItemAutomationPeer(impl::call_factory<PivotItemAutomationPeer, IPivotItemAutomationPeerFactory>([&](IPivotItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner); }))
    {
    }
    inline PivotItemDataAutomationPeer::PivotItemDataAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer const& parent) :
        PivotItemDataAutomationPeer(impl::call_factory<PivotItemDataAutomationPeer, IPivotItemDataAutomationPeerFactory>([&](IPivotItemDataAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent); }))
    {
    }
    inline ProgressBarAutomationPeer::ProgressBarAutomationPeer(winrt::Windows::UI::Xaml::Controls::ProgressBar const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ProgressBarAutomationPeer, IProgressBarAutomationPeerFactory>([&](IProgressBarAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ProgressRingAutomationPeer::ProgressRingAutomationPeer(winrt::Windows::UI::Xaml::Controls::ProgressRing const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ProgressRingAutomationPeer, IProgressRingAutomationPeerFactory>([&](IProgressRingAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline RadioButtonAutomationPeer::RadioButtonAutomationPeer(winrt::Windows::UI::Xaml::Controls::RadioButton const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RadioButtonAutomationPeer, IRadioButtonAutomationPeerFactory>([&](IRadioButtonAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline RangeBaseAutomationPeer::RangeBaseAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RangeBaseAutomationPeer, IRangeBaseAutomationPeerFactory>([&](IRangeBaseAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline RatingControlAutomationPeer::RatingControlAutomationPeer(winrt::Windows::UI::Xaml::Controls::RatingControl const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RatingControlAutomationPeer, IRatingControlAutomationPeerFactory>([&](IRatingControlAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline RepeatButtonAutomationPeer::RepeatButtonAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::RepeatButton const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RepeatButtonAutomationPeer, IRepeatButtonAutomationPeerFactory>([&](IRepeatButtonAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline RichEditBoxAutomationPeer::RichEditBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::RichEditBox const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RichEditBoxAutomationPeer, IRichEditBoxAutomationPeerFactory>([&](IRichEditBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline RichTextBlockAutomationPeer::RichTextBlockAutomationPeer(winrt::Windows::UI::Xaml::Controls::RichTextBlock const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RichTextBlockAutomationPeer, IRichTextBlockAutomationPeerFactory>([&](IRichTextBlockAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline RichTextBlockOverflowAutomationPeer::RichTextBlockOverflowAutomationPeer(winrt::Windows::UI::Xaml::Controls::RichTextBlockOverflow const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RichTextBlockOverflowAutomationPeer, IRichTextBlockOverflowAutomationPeerFactory>([&](IRichTextBlockOverflowAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ScrollBarAutomationPeer::ScrollBarAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::ScrollBar const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ScrollBarAutomationPeer, IScrollBarAutomationPeerFactory>([&](IScrollBarAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ScrollViewerAutomationPeer::ScrollViewerAutomationPeer(winrt::Windows::UI::Xaml::Controls::ScrollViewer const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ScrollViewerAutomationPeer, IScrollViewerAutomationPeerFactory>([&](IScrollViewerAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline SearchBoxAutomationPeer::SearchBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::SearchBox const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SearchBoxAutomationPeer, ISearchBoxAutomationPeerFactory>([&](ISearchBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline SelectorAutomationPeer::SelectorAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::Selector const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SelectorAutomationPeer, ISelectorAutomationPeerFactory>([&](ISelectorAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline SelectorItemAutomationPeer::SelectorItemAutomationPeer(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const& parent)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SelectorItemAutomationPeer, ISelectorItemAutomationPeerFactory>([&](ISelectorItemAutomationPeerFactory const& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
    }
    inline SemanticZoomAutomationPeer::SemanticZoomAutomationPeer(winrt::Windows::UI::Xaml::Controls::SemanticZoom const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SemanticZoomAutomationPeer, ISemanticZoomAutomationPeerFactory>([&](ISemanticZoomAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline SettingsFlyoutAutomationPeer::SettingsFlyoutAutomationPeer(winrt::Windows::UI::Xaml::Controls::SettingsFlyout const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SettingsFlyoutAutomationPeer, ISettingsFlyoutAutomationPeerFactory>([&](ISettingsFlyoutAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline SliderAutomationPeer::SliderAutomationPeer(winrt::Windows::UI::Xaml::Controls::Slider const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SliderAutomationPeer, ISliderAutomationPeerFactory>([&](ISliderAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline TextBlockAutomationPeer::TextBlockAutomationPeer(winrt::Windows::UI::Xaml::Controls::TextBlock const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<TextBlockAutomationPeer, ITextBlockAutomationPeerFactory>([&](ITextBlockAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline TextBoxAutomationPeer::TextBoxAutomationPeer(winrt::Windows::UI::Xaml::Controls::TextBox const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<TextBoxAutomationPeer, ITextBoxAutomationPeerFactory>([&](ITextBoxAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ThumbAutomationPeer::ThumbAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::Thumb const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ThumbAutomationPeer, IThumbAutomationPeerFactory>([&](IThumbAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline TimePickerAutomationPeer::TimePickerAutomationPeer(winrt::Windows::UI::Xaml::Controls::TimePicker const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<TimePickerAutomationPeer, ITimePickerAutomationPeerFactory>([&](ITimePickerAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ToggleButtonAutomationPeer::ToggleButtonAutomationPeer(winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ToggleButtonAutomationPeer, IToggleButtonAutomationPeerFactory>([&](IToggleButtonAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ToggleMenuFlyoutItemAutomationPeer::ToggleMenuFlyoutItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ToggleMenuFlyoutItemAutomationPeer, IToggleMenuFlyoutItemAutomationPeerFactory>([&](IToggleMenuFlyoutItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline ToggleSwitchAutomationPeer::ToggleSwitchAutomationPeer(winrt::Windows::UI::Xaml::Controls::ToggleSwitch const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ToggleSwitchAutomationPeer, IToggleSwitchAutomationPeerFactory>([&](IToggleSwitchAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline TreeViewItemAutomationPeer::TreeViewItemAutomationPeer(winrt::Windows::UI::Xaml::Controls::TreeViewItem const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<TreeViewItemAutomationPeer, ITreeViewItemAutomationPeerFactory>([&](ITreeViewItemAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    inline TreeViewListAutomationPeer::TreeViewListAutomationPeer(winrt::Windows::UI::Xaml::Controls::TreeViewList const& owner)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<TreeViewListAutomationPeer, ITreeViewListAutomationPeerFactory>([&](ITreeViewListAutomationPeerFactory const& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) IAutomationPeerOverridesT<D>::GetPatternCore(winrt::Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface) const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetPatternCore(patternInterface);
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetAcceleratorKeyCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetAcceleratorKeyCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetAccessKeyCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetAccessKeyCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationControlType) IAutomationPeerOverridesT<D>::GetAutomationControlTypeCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetAutomationControlTypeCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetAutomationIdCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetAutomationIdCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) IAutomationPeerOverridesT<D>::GetBoundingRectangleCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetBoundingRectangleCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) IAutomationPeerOverridesT<D>::GetChildrenCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetChildrenCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetClassNameCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetClassNameCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) IAutomationPeerOverridesT<D>::GetClickablePointCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetClickablePointCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetHelpTextCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetHelpTextCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetItemStatusCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetItemStatusCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetItemTypeCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetItemTypeCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) IAutomationPeerOverridesT<D>::GetLabeledByCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetLabeledByCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetLocalizedControlTypeCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetLocalizedControlTypeCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverridesT<D>::GetNameCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetNameCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationOrientation) IAutomationPeerOverridesT<D>::GetOrientationCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetOrientationCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::HasKeyboardFocusCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().HasKeyboardFocusCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::IsContentElementCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().IsContentElementCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::IsControlElementCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().IsControlElementCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::IsEnabledCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().IsEnabledCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::IsKeyboardFocusableCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().IsKeyboardFocusableCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::IsOffscreenCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().IsOffscreenCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::IsPasswordCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().IsPasswordCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverridesT<D>::IsRequiredForFormCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().IsRequiredForFormCore();
    }
    template <typename D> WINRT_IMPL_AUTO(void) IAutomationPeerOverridesT<D>::SetFocusCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().SetFocusCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer) IAutomationPeerOverridesT<D>::GetPeerFromPointCore(winrt::Windows::Foundation::Point const& point) const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetPeerFromPointCore(point);
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting) IAutomationPeerOverridesT<D>::GetLiveSettingCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides>().GetLiveSettingCore();
    }
    template <typename D> WINRT_IMPL_AUTO(void) IAutomationPeerOverrides2T<D>::ShowContextMenuCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides2>().ShowContextMenuCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) IAutomationPeerOverrides2T<D>::GetControlledPeersCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides2>().GetControlledPeersCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) IAutomationPeerOverrides3T<D>::NavigateCore(winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
    {
        return shim().template try_as<IAutomationPeerOverrides3>().NavigateCore(direction);
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) IAutomationPeerOverrides3T<D>::GetElementFromPointCore(winrt::Windows::Foundation::Point const& pointInWindowCoordinates) const
    {
        return shim().template try_as<IAutomationPeerOverrides3>().GetElementFromPointCore(pointInWindowCoordinates);
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) IAutomationPeerOverrides3T<D>::GetFocusedElementCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides3>().GetFocusedElementCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>) IAutomationPeerOverrides3T<D>::GetAnnotationsCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides3>().GetAnnotationsCore();
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) IAutomationPeerOverrides3T<D>::GetPositionInSetCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides3>().GetPositionInSetCore();
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) IAutomationPeerOverrides3T<D>::GetSizeOfSetCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides3>().GetSizeOfSetCore();
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) IAutomationPeerOverrides3T<D>::GetLevelCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides3>().GetLevelCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType) IAutomationPeerOverrides4T<D>::GetLandmarkTypeCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides4>().GetLandmarkTypeCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverrides4T<D>::GetLocalizedLandmarkTypeCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides4>().GetLocalizedLandmarkTypeCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverrides5T<D>::IsPeripheralCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides5>().IsPeripheralCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverrides5T<D>::IsDataValidForFormCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides5>().IsDataValidForFormCore();
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) IAutomationPeerOverrides5T<D>::GetFullDescriptionCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides5>().GetFullDescriptionCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) IAutomationPeerOverrides5T<D>::GetDescribedByCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides5>().GetDescribedByCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) IAutomationPeerOverrides5T<D>::GetFlowsToCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides5>().GetFlowsToCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer>) IAutomationPeerOverrides5T<D>::GetFlowsFromCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides5>().GetFlowsFromCore();
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) IAutomationPeerOverrides6T<D>::GetCultureCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides6>().GetCultureCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel) IAutomationPeerOverrides8T<D>::GetHeadingLevelCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides8>().GetHeadingLevelCore();
    }
    template <typename D> WINRT_IMPL_AUTO(bool) IAutomationPeerOverrides9T<D>::IsDialogCore() const
    {
        return shim().template try_as<IAutomationPeerOverrides9>().IsDialogCore();
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer) IItemsControlAutomationPeerOverrides2T<D>::OnCreateItemAutomationPeer(winrt::Windows::Foundation::IInspectable const& item) const
    {
        return shim().template try_as<IItemsControlAutomationPeerOverrides2>().OnCreateItemAutomationPeer(item);
    }
    template <typename D, typename... Interfaces>
    struct AppBarAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, AppBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = AppBarAutomationPeer;
    protected:
        AppBarAutomationPeerT(winrt::Windows::UI::Xaml::Controls::AppBar const& owner)
        {
            impl::call_factory<AppBarAutomationPeer, IAppBarAutomationPeerFactory>([&](IAppBarAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct AppBarButtonAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, AppBarButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = AppBarButtonAutomationPeer;
    protected:
        AppBarButtonAutomationPeerT(winrt::Windows::UI::Xaml::Controls::AppBarButton const& owner)
        {
            impl::call_factory<AppBarButtonAutomationPeer, IAppBarButtonAutomationPeerFactory>([&](IAppBarButtonAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct AppBarToggleButtonAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, AppBarToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = AppBarToggleButtonAutomationPeer;
    protected:
        AppBarToggleButtonAutomationPeerT(winrt::Windows::UI::Xaml::Controls::AppBarToggleButton const& owner)
        {
            impl::call_factory<AppBarToggleButtonAutomationPeer, IAppBarToggleButtonAutomationPeerFactory>([&](IAppBarToggleButtonAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct AutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = AutomationPeer;
    protected:
        AutomationPeerT()
        {
            impl::call_factory<AutomationPeer, IAutomationPeerFactory>([&](IAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ButtonAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ButtonAutomationPeer;
    protected:
        ButtonAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Button const& owner)
        {
            impl::call_factory<ButtonAutomationPeer, IButtonAutomationPeerFactory>([&](IButtonAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ButtonBaseAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ButtonBaseAutomationPeer;
    protected:
        ButtonBaseAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::ButtonBase const& owner)
        {
            impl::call_factory<ButtonBaseAutomationPeer, IButtonBaseAutomationPeerFactory>([&](IButtonBaseAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct CalendarDatePickerAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider, winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, CalendarDatePickerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = CalendarDatePickerAutomationPeer;
    protected:
        CalendarDatePickerAutomationPeerT(winrt::Windows::UI::Xaml::Controls::CalendarDatePicker const& owner)
        {
            impl::call_factory<CalendarDatePickerAutomationPeer, ICalendarDatePickerAutomationPeerFactory>([&](ICalendarDatePickerAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider>::SetValue;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::IDependencyObject>::SetValue;
    };
    template <typename D, typename... Interfaces>
    struct CaptureElementAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, CaptureElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = CaptureElementAutomationPeer;
    protected:
        CaptureElementAutomationPeerT(winrt::Windows::UI::Xaml::Controls::CaptureElement const& owner)
        {
            impl::call_factory<CaptureElementAutomationPeer, ICaptureElementAutomationPeerFactory>([&](ICaptureElementAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct CheckBoxAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, CheckBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = CheckBoxAutomationPeer;
    protected:
        CheckBoxAutomationPeerT(winrt::Windows::UI::Xaml::Controls::CheckBox const& owner)
        {
            impl::call_factory<CheckBoxAutomationPeer, ICheckBoxAutomationPeerFactory>([&](ICheckBoxAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ColorPickerSliderAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ColorPickerSliderAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ColorPickerSliderAutomationPeer;
    protected:
        ColorPickerSliderAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const& owner)
        {
            impl::call_factory<ColorPickerSliderAutomationPeer, IColorPickerSliderAutomationPeerFactory>([&](IColorPickerSliderAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider>::SetValue;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::IDependencyObject>::SetValue;
    };
    template <typename D, typename... Interfaces>
    struct ColorSpectrumAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ColorSpectrumAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ColorSpectrumAutomationPeer;
    protected:
        ColorSpectrumAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const& owner)
        {
            impl::call_factory<ColorSpectrumAutomationPeer, IColorSpectrumAutomationPeerFactory>([&](IColorSpectrumAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ComboBoxAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider, winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ComboBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ComboBoxAutomationPeer;
    protected:
        ComboBoxAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ComboBox const& owner)
        {
            impl::call_factory<ComboBoxAutomationPeer, IComboBoxAutomationPeerFactory>([&](IComboBoxAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider>::SetValue;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::IDependencyObject>::SetValue;
    };
    template <typename D, typename... Interfaces>
    struct ComboBoxItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ComboBoxItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ComboBoxItemAutomationPeer;
    protected:
        ComboBoxItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ComboBoxItem const& owner)
        {
            impl::call_factory<ComboBoxItemAutomationPeer, IComboBoxItemAutomationPeerFactory>([&](IComboBoxItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ComboBoxItemDataAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ComboBoxItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ComboBoxItemDataAutomationPeer;
    protected:
        ComboBoxItemDataAutomationPeerT(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const& parent)
        {
            impl::call_factory<ComboBoxItemDataAutomationPeer, IComboBoxItemDataAutomationPeerFactory>([&](IComboBoxItemDataAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct DatePickerAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, DatePickerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = DatePickerAutomationPeer;
    protected:
        DatePickerAutomationPeerT(winrt::Windows::UI::Xaml::Controls::DatePicker const& owner)
        {
            impl::call_factory<DatePickerAutomationPeer, IDatePickerAutomationPeerFactory>([&](IDatePickerAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FlipViewAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FlipViewAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = FlipViewAutomationPeer;
    protected:
        FlipViewAutomationPeerT(winrt::Windows::UI::Xaml::Controls::FlipView const& owner)
        {
            impl::call_factory<FlipViewAutomationPeer, IFlipViewAutomationPeerFactory>([&](IFlipViewAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FlipViewItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FlipViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = FlipViewItemAutomationPeer;
    protected:
        FlipViewItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::FlipViewItem const& owner)
        {
            impl::call_factory<FlipViewItemAutomationPeer, IFlipViewItemAutomationPeerFactory>([&](IFlipViewItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FlipViewItemDataAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FlipViewItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = FlipViewItemDataAutomationPeer;
    protected:
        FlipViewItemDataAutomationPeerT(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const& parent)
        {
            impl::call_factory<FlipViewItemDataAutomationPeer, IFlipViewItemDataAutomationPeerFactory>([&](IFlipViewItemDataAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FlyoutPresenterAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FlyoutPresenterAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = FlyoutPresenterAutomationPeer;
    protected:
        FlyoutPresenterAutomationPeerT(winrt::Windows::UI::Xaml::Controls::FlyoutPresenter const& owner)
        {
            impl::call_factory<FlyoutPresenterAutomationPeer, IFlyoutPresenterAutomationPeerFactory>([&](IFlyoutPresenterAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct FrameworkElementAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = FrameworkElementAutomationPeer;
    protected:
        FrameworkElementAutomationPeerT(winrt::Windows::UI::Xaml::FrameworkElement const& owner)
        {
            impl::call_factory<FrameworkElementAutomationPeer, IFrameworkElementAutomationPeerFactory>([&](IFrameworkElementAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct GridViewAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, GridViewAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = GridViewAutomationPeer;
    protected:
        GridViewAutomationPeerT(winrt::Windows::UI::Xaml::Controls::GridView const& owner)
        {
            impl::call_factory<GridViewAutomationPeer, IGridViewAutomationPeerFactory>([&](IGridViewAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct GridViewHeaderItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, GridViewHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = GridViewHeaderItemAutomationPeer;
    protected:
        GridViewHeaderItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::GridViewHeaderItem const& owner)
        {
            impl::call_factory<GridViewHeaderItemAutomationPeer, IGridViewHeaderItemAutomationPeerFactory>([&](IGridViewHeaderItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct GridViewItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, GridViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = GridViewItemAutomationPeer;
    protected:
        GridViewItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::GridViewItem const& owner)
        {
            impl::call_factory<GridViewItemAutomationPeer, IGridViewItemAutomationPeerFactory>([&](IGridViewItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct GridViewItemDataAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, GridViewItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = GridViewItemDataAutomationPeer;
    protected:
        GridViewItemDataAutomationPeerT(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const& parent)
        {
            impl::call_factory<GridViewItemDataAutomationPeer, IGridViewItemDataAutomationPeerFactory>([&](IGridViewItemDataAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct GroupItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, GroupItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = GroupItemAutomationPeer;
    protected:
        GroupItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::GroupItem const& owner)
        {
            impl::call_factory<GroupItemAutomationPeer, IGroupItemAutomationPeerFactory>([&](IGroupItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct HubAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, HubAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = HubAutomationPeer;
    protected:
        HubAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Hub const& owner)
        {
            impl::call_factory<HubAutomationPeer, IHubAutomationPeerFactory>([&](IHubAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct HubSectionAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, HubSectionAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = HubSectionAutomationPeer;
    protected:
        HubSectionAutomationPeerT(winrt::Windows::UI::Xaml::Controls::HubSection const& owner)
        {
            impl::call_factory<HubSectionAutomationPeer, IHubSectionAutomationPeerFactory>([&](IHubSectionAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct HyperlinkButtonAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, HyperlinkButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = HyperlinkButtonAutomationPeer;
    protected:
        HyperlinkButtonAutomationPeerT(winrt::Windows::UI::Xaml::Controls::HyperlinkButton const& owner)
        {
            impl::call_factory<HyperlinkButtonAutomationPeer, IHyperlinkButtonAutomationPeerFactory>([&](IHyperlinkButtonAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ImageAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ImageAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ImageAutomationPeer;
    protected:
        ImageAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Image const& owner)
        {
            impl::call_factory<ImageAutomationPeer, IImageAutomationPeerFactory>([&](IImageAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ItemAutomationPeer;
    protected:
        ItemAutomationPeerT(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const& parent)
        {
            impl::call_factory<ItemAutomationPeer, IItemAutomationPeerFactory>([&](IItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ItemsControlAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ItemsControlAutomationPeer;
    protected:
        ItemsControlAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ItemsControl const& owner)
        {
            impl::call_factory<ItemsControlAutomationPeer, IItemsControlAutomationPeerFactory>([&](IItemsControlAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListBoxAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListBoxAutomationPeer;
    protected:
        ListBoxAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ListBox const& owner)
        {
            impl::call_factory<ListBoxAutomationPeer, IListBoxAutomationPeerFactory>([&](IListBoxAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListBoxItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListBoxItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListBoxItemAutomationPeer;
    protected:
        ListBoxItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ListBoxItem const& owner)
        {
            impl::call_factory<ListBoxItemAutomationPeer, IListBoxItemAutomationPeerFactory>([&](IListBoxItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListBoxItemDataAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListBoxItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListBoxItemDataAutomationPeer;
    protected:
        ListBoxItemDataAutomationPeerT(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const& parent)
        {
            impl::call_factory<ListBoxItemDataAutomationPeer, IListBoxItemDataAutomationPeerFactory>([&](IListBoxItemDataAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListViewAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListViewAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListViewAutomationPeer;
    protected:
        ListViewAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ListView const& owner)
        {
            impl::call_factory<ListViewAutomationPeer, IListViewAutomationPeerFactory>([&](IListViewAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListViewBaseAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListViewBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListViewBaseAutomationPeer;
    protected:
        ListViewBaseAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ListViewBase const& owner)
        {
            impl::call_factory<ListViewBaseAutomationPeer, IListViewBaseAutomationPeerFactory>([&](IListViewBaseAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListViewBaseHeaderItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListViewBaseHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListViewBaseHeaderItemAutomationPeer;
    protected:
        ListViewBaseHeaderItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ListViewBaseHeaderItem const& owner)
        {
            impl::call_factory<ListViewBaseHeaderItemAutomationPeer, IListViewBaseHeaderItemAutomationPeerFactory>([&](IListViewBaseHeaderItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListViewHeaderItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListViewHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListViewHeaderItemAutomationPeer;
    protected:
        ListViewHeaderItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ListViewHeaderItem const& owner)
        {
            impl::call_factory<ListViewHeaderItemAutomationPeer, IListViewHeaderItemAutomationPeerFactory>([&](IListViewHeaderItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListViewItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListViewItemAutomationPeer;
    protected:
        ListViewItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ListViewItem const& owner)
        {
            impl::call_factory<ListViewItemAutomationPeer, IListViewItemAutomationPeerFactory>([&](IListViewItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ListViewItemDataAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ListViewItemDataAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ListViewItemDataAutomationPeer;
    protected:
        ListViewItemDataAutomationPeerT(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const& parent)
        {
            impl::call_factory<ListViewItemDataAutomationPeer, IListViewItemDataAutomationPeerFactory>([&](IListViewItemDataAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct MediaElementAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, MediaElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = MediaElementAutomationPeer;
    protected:
        MediaElementAutomationPeerT(winrt::Windows::UI::Xaml::Controls::MediaElement const& owner)
        {
            impl::call_factory<MediaElementAutomationPeer, IMediaElementAutomationPeerFactory>([&](IMediaElementAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct MediaPlayerElementAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, MediaPlayerElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = MediaPlayerElementAutomationPeer;
    protected:
        MediaPlayerElementAutomationPeerT(winrt::Windows::UI::Xaml::Controls::MediaPlayerElement const& owner)
        {
            impl::call_factory<MediaPlayerElementAutomationPeer, IMediaPlayerElementAutomationPeerFactory>([&](IMediaPlayerElementAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct MediaTransportControlsAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, MediaTransportControlsAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = MediaTransportControlsAutomationPeer;
    protected:
        MediaTransportControlsAutomationPeerT(winrt::Windows::UI::Xaml::Controls::MediaTransportControls const& owner)
        {
            impl::call_factory<MediaTransportControlsAutomationPeer, IMediaTransportControlsAutomationPeerFactory>([&](IMediaTransportControlsAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct MenuBarAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, MenuBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = MenuBarAutomationPeer;
    protected:
        MenuBarAutomationPeerT(winrt::Windows::UI::Xaml::Controls::MenuBar const& owner)
        {
            impl::call_factory<MenuBarAutomationPeer, IMenuBarAutomationPeerFactory>([&](IMenuBarAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct MenuBarItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, MenuBarItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = MenuBarItemAutomationPeer;
    protected:
        MenuBarItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::MenuBarItem const& owner)
        {
            impl::call_factory<MenuBarItemAutomationPeer, IMenuBarItemAutomationPeerFactory>([&](IMenuBarItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct MenuFlyoutItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, MenuFlyoutItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = MenuFlyoutItemAutomationPeer;
    protected:
        MenuFlyoutItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::MenuFlyoutItem const& owner)
        {
            impl::call_factory<MenuFlyoutItemAutomationPeer, IMenuFlyoutItemAutomationPeerFactory>([&](IMenuFlyoutItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct MenuFlyoutPresenterAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, MenuFlyoutPresenterAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = MenuFlyoutPresenterAutomationPeer;
    protected:
        MenuFlyoutPresenterAutomationPeerT(winrt::Windows::UI::Xaml::Controls::MenuFlyoutPresenter const& owner)
        {
            impl::call_factory<MenuFlyoutPresenterAutomationPeer, IMenuFlyoutPresenterAutomationPeerFactory>([&](IMenuFlyoutPresenterAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct NavigationViewItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, NavigationViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = NavigationViewItemAutomationPeer;
    protected:
        NavigationViewItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::NavigationViewItem const& owner)
        {
            impl::call_factory<NavigationViewItemAutomationPeer, INavigationViewItemAutomationPeerFactory>([&](INavigationViewItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct PasswordBoxAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, PasswordBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = PasswordBoxAutomationPeer;
    protected:
        PasswordBoxAutomationPeerT(winrt::Windows::UI::Xaml::Controls::PasswordBox const& owner)
        {
            impl::call_factory<PasswordBoxAutomationPeer, IPasswordBoxAutomationPeerFactory>([&](IPasswordBoxAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct PersonPictureAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, PersonPictureAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = PersonPictureAutomationPeer;
    protected:
        PersonPictureAutomationPeerT(winrt::Windows::UI::Xaml::Controls::PersonPicture const& owner)
        {
            impl::call_factory<PersonPictureAutomationPeer, IPersonPictureAutomationPeerFactory>([&](IPersonPictureAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ProgressBarAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ProgressBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ProgressBarAutomationPeer;
    protected:
        ProgressBarAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ProgressBar const& owner)
        {
            impl::call_factory<ProgressBarAutomationPeer, IProgressBarAutomationPeerFactory>([&](IProgressBarAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider>::SetValue;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::IDependencyObject>::SetValue;
    };
    template <typename D, typename... Interfaces>
    struct ProgressRingAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ProgressRingAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ProgressRingAutomationPeer;
    protected:
        ProgressRingAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ProgressRing const& owner)
        {
            impl::call_factory<ProgressRingAutomationPeer, IProgressRingAutomationPeerFactory>([&](IProgressRingAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RadioButtonAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RadioButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = RadioButtonAutomationPeer;
    protected:
        RadioButtonAutomationPeerT(winrt::Windows::UI::Xaml::Controls::RadioButton const& owner)
        {
            impl::call_factory<RadioButtonAutomationPeer, IRadioButtonAutomationPeerFactory>([&](IRadioButtonAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RangeBaseAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = RangeBaseAutomationPeer;
    protected:
        RangeBaseAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::RangeBase const& owner)
        {
            impl::call_factory<RangeBaseAutomationPeer, IRangeBaseAutomationPeerFactory>([&](IRangeBaseAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider>::SetValue;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::IDependencyObject>::SetValue;
    };
    template <typename D, typename... Interfaces>
    struct RatingControlAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RatingControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = RatingControlAutomationPeer;
    protected:
        RatingControlAutomationPeerT(winrt::Windows::UI::Xaml::Controls::RatingControl const& owner)
        {
            impl::call_factory<RatingControlAutomationPeer, IRatingControlAutomationPeerFactory>([&](IRatingControlAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RepeatButtonAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RepeatButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = RepeatButtonAutomationPeer;
    protected:
        RepeatButtonAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::RepeatButton const& owner)
        {
            impl::call_factory<RepeatButtonAutomationPeer, IRepeatButtonAutomationPeerFactory>([&](IRepeatButtonAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RichEditBoxAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RichEditBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = RichEditBoxAutomationPeer;
    protected:
        RichEditBoxAutomationPeerT(winrt::Windows::UI::Xaml::Controls::RichEditBox const& owner)
        {
            impl::call_factory<RichEditBoxAutomationPeer, IRichEditBoxAutomationPeerFactory>([&](IRichEditBoxAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RichTextBlockAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RichTextBlockAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = RichTextBlockAutomationPeer;
    protected:
        RichTextBlockAutomationPeerT(winrt::Windows::UI::Xaml::Controls::RichTextBlock const& owner)
        {
            impl::call_factory<RichTextBlockAutomationPeer, IRichTextBlockAutomationPeerFactory>([&](IRichTextBlockAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RichTextBlockOverflowAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RichTextBlockOverflowAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = RichTextBlockOverflowAutomationPeer;
    protected:
        RichTextBlockOverflowAutomationPeerT(winrt::Windows::UI::Xaml::Controls::RichTextBlockOverflow const& owner)
        {
            impl::call_factory<RichTextBlockOverflowAutomationPeer, IRichTextBlockOverflowAutomationPeerFactory>([&](IRichTextBlockOverflowAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ScrollBarAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ScrollBarAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ScrollBarAutomationPeer;
    protected:
        ScrollBarAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::ScrollBar const& owner)
        {
            impl::call_factory<ScrollBarAutomationPeer, IScrollBarAutomationPeerFactory>([&](IScrollBarAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider>::SetValue;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::IDependencyObject>::SetValue;
    };
    template <typename D, typename... Interfaces>
    struct ScrollViewerAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ScrollViewerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ScrollViewerAutomationPeer;
    protected:
        ScrollViewerAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ScrollViewer const& owner)
        {
            impl::call_factory<ScrollViewerAutomationPeer, IScrollViewerAutomationPeerFactory>([&](IScrollViewerAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SearchBoxAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SearchBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = SearchBoxAutomationPeer;
    protected:
        SearchBoxAutomationPeerT(winrt::Windows::UI::Xaml::Controls::SearchBox const& owner)
        {
            impl::call_factory<SearchBoxAutomationPeer, ISearchBoxAutomationPeerFactory>([&](ISearchBoxAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SelectorAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = SelectorAutomationPeer;
    protected:
        SelectorAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::Selector const& owner)
        {
            impl::call_factory<SelectorAutomationPeer, ISelectorAutomationPeerFactory>([&](ISelectorAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SelectorItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SelectorItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = SelectorItemAutomationPeer;
    protected:
        SelectorItemAutomationPeerT(winrt::Windows::Foundation::IInspectable const& item, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const& parent)
        {
            impl::call_factory<SelectorItemAutomationPeer, ISelectorItemAutomationPeerFactory>([&](ISelectorItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SemanticZoomAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SemanticZoomAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = SemanticZoomAutomationPeer;
    protected:
        SemanticZoomAutomationPeerT(winrt::Windows::UI::Xaml::Controls::SemanticZoom const& owner)
        {
            impl::call_factory<SemanticZoomAutomationPeer, ISemanticZoomAutomationPeerFactory>([&](ISemanticZoomAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SettingsFlyoutAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SettingsFlyoutAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = SettingsFlyoutAutomationPeer;
    protected:
        SettingsFlyoutAutomationPeerT(winrt::Windows::UI::Xaml::Controls::SettingsFlyout const& owner)
        {
            impl::call_factory<SettingsFlyoutAutomationPeer, ISettingsFlyoutAutomationPeerFactory>([&](ISettingsFlyoutAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SliderAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SliderAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = SliderAutomationPeer;
    protected:
        SliderAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Slider const& owner)
        {
            impl::call_factory<SliderAutomationPeer, ISliderAutomationPeerFactory>([&](ISliderAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
        using impl::consume_t<D, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider>::SetValue;
        using impl::consume_t<D, winrt::Windows::UI::Xaml::IDependencyObject>::SetValue;
    };
    template <typename D, typename... Interfaces>
    struct TextBlockAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, TextBlockAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = TextBlockAutomationPeer;
    protected:
        TextBlockAutomationPeerT(winrt::Windows::UI::Xaml::Controls::TextBlock const& owner)
        {
            impl::call_factory<TextBlockAutomationPeer, ITextBlockAutomationPeerFactory>([&](ITextBlockAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct TextBoxAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, TextBoxAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = TextBoxAutomationPeer;
    protected:
        TextBoxAutomationPeerT(winrt::Windows::UI::Xaml::Controls::TextBox const& owner)
        {
            impl::call_factory<TextBoxAutomationPeer, ITextBoxAutomationPeerFactory>([&](ITextBoxAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ThumbAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ThumbAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ThumbAutomationPeer;
    protected:
        ThumbAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::Thumb const& owner)
        {
            impl::call_factory<ThumbAutomationPeer, IThumbAutomationPeerFactory>([&](IThumbAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct TimePickerAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, TimePickerAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = TimePickerAutomationPeer;
    protected:
        TimePickerAutomationPeerT(winrt::Windows::UI::Xaml::Controls::TimePicker const& owner)
        {
            impl::call_factory<TimePickerAutomationPeer, ITimePickerAutomationPeerFactory>([&](ITimePickerAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ToggleButtonAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ToggleButtonAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ToggleButtonAutomationPeer;
    protected:
        ToggleButtonAutomationPeerT(winrt::Windows::UI::Xaml::Controls::Primitives::ToggleButton const& owner)
        {
            impl::call_factory<ToggleButtonAutomationPeer, IToggleButtonAutomationPeerFactory>([&](IToggleButtonAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ToggleMenuFlyoutItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ToggleMenuFlyoutItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ToggleMenuFlyoutItemAutomationPeer;
    protected:
        ToggleMenuFlyoutItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const& owner)
        {
            impl::call_factory<ToggleMenuFlyoutItemAutomationPeer, IToggleMenuFlyoutItemAutomationPeerFactory>([&](IToggleMenuFlyoutItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ToggleSwitchAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, ToggleSwitchAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = ToggleSwitchAutomationPeer;
    protected:
        ToggleSwitchAutomationPeerT(winrt::Windows::UI::Xaml::Controls::ToggleSwitch const& owner)
        {
            impl::call_factory<ToggleSwitchAutomationPeer, IToggleSwitchAutomationPeerFactory>([&](IToggleSwitchAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct TreeViewItemAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, TreeViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = TreeViewItemAutomationPeer;
    protected:
        TreeViewItemAutomationPeerT(winrt::Windows::UI::Xaml::Controls::TreeViewItem const& owner)
        {
            impl::call_factory<TreeViewItemAutomationPeer, ITreeViewItemAutomationPeerFactory>([&](ITreeViewItemAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct TreeViewListAutomationPeerT :
        implements<D, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, TreeViewListAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer, winrt::Windows::UI::Xaml::DependencyObject>,
        winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
    {
        using composable = TreeViewListAutomationPeer;
    protected:
        TreeViewListAutomationPeerT(winrt::Windows::UI::Xaml::Controls::TreeViewList const& owner)
        {
            impl::call_factory<TreeViewListAutomationPeer, ITreeViewListAutomationPeerFactory>([&](ITreeViewListAutomationPeerFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IInkToolbarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListPickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMapControlAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::DatePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::HubAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::InkToolbarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListPickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MapControlAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TimePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
