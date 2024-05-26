// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Automation_Provider_H
#define WINRT_Windows_UI_Xaml_Automation_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.Automation.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Peers.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Text.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::AnnotationTypeId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_AnnotationTypeId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::AnnotationTypeName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_AnnotationTypeName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::Author() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_Author(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::DateTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_DateTime(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_IAnnotationProvider<D>::Target() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider)->get_Target(&value));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Provider_ICustomNavigationProvider<D>::NavigateCustom(winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider)->NavigateCustom(static_cast<int32_t>(direction), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::DockPosition) consume_Windows_UI_Xaml_Automation_Provider_IDockProvider<D>::DockPosition() const
    {
        winrt::Windows::UI::Xaml::Automation::DockPosition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDockProvider)->get_DockPosition(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IDockProvider<D>::SetDockPosition(winrt::Windows::UI::Xaml::Automation::DockPosition const& dockPosition) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDockProvider)->SetDockPosition(static_cast<int32_t>(dockPosition)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::IsGrabbed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider)->get_IsGrabbed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::DropEffect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider)->get_DropEffect(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<hstring>) consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::DropEffects() const
    {
        uint32_t value_impl_size{};
        void** value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider)->get_DropEffects(&value_impl_size, &value));
        return com_array<hstring>{ value, value_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_IDragProvider<D>::GetGrabbedItems() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider)->GetGrabbedItems(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IDropTargetProvider<D>::DropEffect() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider)->get_DropEffect(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<hstring>) consume_Windows_UI_Xaml_Automation_Provider_IDropTargetProvider<D>::DropEffects() const
    {
        uint32_t value_impl_size{};
        void** value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider)->get_DropEffects(&value_impl_size, &value));
        return com_array<hstring>{ value, value_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::ExpandCollapseState) consume_Windows_UI_Xaml_Automation_Provider_IExpandCollapseProvider<D>::ExpandCollapseState() const
    {
        winrt::Windows::UI::Xaml::Automation::ExpandCollapseState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider)->get_ExpandCollapseState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IExpandCollapseProvider<D>::Collapse() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider)->Collapse());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IExpandCollapseProvider<D>::Expand() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider)->Expand());
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::Column() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_Column(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::ColumnSpan() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_ColumnSpan(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::ContainingGrid() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_ContainingGrid(&value));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::Row() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_Row(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IGridItemProvider<D>::RowSpan() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider)->get_RowSpan(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IGridProvider<D>::ColumnCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider)->get_ColumnCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IGridProvider<D>::RowCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider)->get_RowCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_IGridProvider<D>::GetItem(int32_t row, int32_t column) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider)->GetItem(row, column, &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IInvokeProvider<D>::Invoke() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider)->Invoke());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_IItemContainerProvider<D>::FindItemByProperty(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& startAfter, winrt::Windows::UI::Xaml::Automation::AutomationProperty const& automationProperty, winrt::Windows::Foundation::IInspectable const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider)->FindItemByProperty(*(void**)(&startAfter), *(void**)(&automationProperty), *(void**)(&value), &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::CurrentView() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->get_CurrentView(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<int32_t>) consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::GetSupportedViews() const
    {
        uint32_t result_impl_size{};
        int32_t* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->GetSupportedViews(&result_impl_size, &result));
        return com_array<int32_t>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::GetViewName(int32_t viewId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->GetViewName(viewId, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IMultipleViewProvider<D>::SetCurrentView(int32_t viewId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider)->SetCurrentView(viewId));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Provider_IObjectModelProvider<D>::GetUnderlyingObjectModel() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IObjectModelProvider)->GetUnderlyingObjectModel(&result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::IsReadOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_IsReadOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::LargeChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_LargeChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::Maximum() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_Maximum(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::Minimum() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_Minimum(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::SmallChange() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_SmallChange(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::Value() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->get_Value(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IRangeValueProvider<D>::SetValue(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider)->SetValue(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IScrollItemProvider<D>::ScrollIntoView() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider)->ScrollIntoView());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::HorizontallyScrollable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_HorizontallyScrollable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::HorizontalScrollPercent() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_HorizontalScrollPercent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::HorizontalViewSize() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_HorizontalViewSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::VerticallyScrollable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_VerticallyScrollable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::VerticalScrollPercent() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_VerticalScrollPercent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::VerticalViewSize() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->get_VerticalViewSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::Scroll(winrt::Windows::UI::Xaml::Automation::ScrollAmount const& horizontalAmount, winrt::Windows::UI::Xaml::Automation::ScrollAmount const& verticalAmount) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->Scroll(static_cast<int32_t>(horizontalAmount), static_cast<int32_t>(verticalAmount)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IScrollProvider<D>::SetScrollPercent(double horizontalPercent, double verticalPercent) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider)->SetScrollPercent(horizontalPercent, verticalPercent));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::IsSelected() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->get_IsSelected(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::SelectionContainer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->get_SelectionContainer(&value));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::AddToSelection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->AddToSelection());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::RemoveFromSelection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->RemoveFromSelection());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ISelectionItemProvider<D>::Select() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider)->Select());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ISelectionProvider<D>::CanSelectMultiple() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider)->get_CanSelectMultiple(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ISelectionProvider<D>::IsSelectionRequired() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider)->get_IsSelectionRequired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_ISelectionProvider<D>::GetSelection() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider)->GetSelection(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetItemProvider<D>::Formula() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider)->get_Formula(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetItemProvider<D>::GetAnnotationObjects() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider)->GetAnnotationObjects(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::AnnotationType>) consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetItemProvider<D>::GetAnnotationTypes() const
    {
        uint32_t result_impl_size{};
        int32_t* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider)->GetAnnotationTypes(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::AnnotationType>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_ISpreadsheetProvider<D>::GetItemByName(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider)->GetItemByName(*(void**)(&name), &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::ExtendedProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_ExtendedProperties(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::FillColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_FillColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::FillPatternColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_FillPatternColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::FillPatternStyle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_FillPatternStyle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::Shape() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_Shape(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::StyleId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_StyleId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IStylesProvider<D>::StyleName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider)->get_StyleName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ISynchronizedInputProvider<D>::Cancel() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider)->Cancel());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ISynchronizedInputProvider<D>::StartListening(winrt::Windows::UI::Xaml::Automation::SynchronizedInputType const& inputType) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider)->StartListening(static_cast<int32_t>(inputType)));
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_ITableItemProvider<D>::GetColumnHeaderItems() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITableItemProvider)->GetColumnHeaderItems(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_ITableItemProvider<D>::GetRowHeaderItems() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITableItemProvider)->GetRowHeaderItems(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::RowOrColumnMajor) consume_Windows_UI_Xaml_Automation_Provider_ITableProvider<D>::RowOrColumnMajor() const
    {
        winrt::Windows::UI::Xaml::Automation::RowOrColumnMajor value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider)->get_RowOrColumnMajor(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_ITableProvider<D>::GetColumnHeaders() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider)->GetColumnHeaders(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_ITableProvider<D>::GetRowHeaders() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider)->GetRowHeaders(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_ITextChildProvider<D>::TextContainer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextChildProvider)->get_TextContainer(&value));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextChildProvider<D>::TextRange() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextChildProvider)->get_TextRange(&value));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextEditProvider<D>::GetActiveComposition() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextEditProvider)->GetActiveComposition(&result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextEditProvider<D>::GetConversionTarget() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextEditProvider)->GetConversionTarget(&result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::DocumentRange() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider)->get_DocumentRange(&value));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::SupportedTextSelection) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::SupportedTextSelection() const
    {
        winrt::Windows::UI::Xaml::Automation::SupportedTextSelection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider)->get_SupportedTextSelection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::GetSelection() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider)->GetSelection(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::GetVisibleRanges() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider)->GetVisibleRanges(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::RangeFromChild(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& childElement) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider)->RangeFromChild(*(void**)(&childElement), &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider<D>::RangeFromPoint(winrt::Windows::Foundation::Point const& screenLocation) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider)->RangeFromPoint(impl::bind_in(screenLocation), &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider2<D>::RangeFromAnnotation(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& annotationElement) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider2)->RangeFromAnnotation(*(void**)(&annotationElement), &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextProvider2<D>::GetCaretRange(bool& isActive) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider2)->GetCaretRange(&isActive, &returnValue));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Clone() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Clone(&result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Compare(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const& textRangeProvider) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Compare(*(void**)(&textRangeProvider), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::CompareEndpoints(winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& endpoint, winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const& textRangeProvider, winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& targetEndpoint) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->CompareEndpoints(static_cast<int32_t>(endpoint), *(void**)(&textRangeProvider), static_cast<int32_t>(targetEndpoint), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::ExpandToEnclosingUnit(winrt::Windows::UI::Xaml::Automation::Text::TextUnit const& unit) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->ExpandToEnclosingUnit(static_cast<int32_t>(unit)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::FindAttribute(int32_t attributeId, winrt::Windows::Foundation::IInspectable const& value, bool backward) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->FindAttribute(attributeId, *(void**)(&value), backward, &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::FindText(param::hstring const& text, bool backward, bool ignoreCase) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->FindText(*(void**)(&text), backward, ignoreCase, &result));
        return winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetAttributeValue(int32_t attributeId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetAttributeValue(attributeId, &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetBoundingRectangles(com_array<double>& returnValue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetBoundingRectangles(impl::put_size_abi(returnValue), put_abi(returnValue)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetEnclosingElement() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetEnclosingElement(&result));
        return winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetText(int32_t maxLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetText(maxLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Move(winrt::Windows::UI::Xaml::Automation::Text::TextUnit const& unit, int32_t count) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Move(static_cast<int32_t>(unit), count, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::MoveEndpointByUnit(winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& endpoint, winrt::Windows::UI::Xaml::Automation::Text::TextUnit const& unit, int32_t count) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->MoveEndpointByUnit(static_cast<int32_t>(endpoint), static_cast<int32_t>(unit), count, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::MoveEndpointByRange(winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& endpoint, winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const& textRangeProvider, winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const& targetEndpoint) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->MoveEndpointByRange(static_cast<int32_t>(endpoint), *(void**)(&textRangeProvider), static_cast<int32_t>(targetEndpoint)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::Select() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->Select());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::AddToSelection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->AddToSelection());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::RemoveFromSelection() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->RemoveFromSelection());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::ScrollIntoView(bool alignToTop) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->ScrollIntoView(alignToTop));
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider<D>::GetChildren() const
    {
        uint32_t result_impl_size{};
        void** result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider)->GetChildren(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITextRangeProvider2<D>::ShowContextMenu() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2)->ShowContextMenu());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::ToggleState) consume_Windows_UI_Xaml_Automation_Provider_IToggleProvider<D>::ToggleState() const
    {
        winrt::Windows::UI::Xaml::Automation::ToggleState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider)->get_ToggleState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IToggleProvider<D>::Toggle() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider)->Toggle());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::CanMove() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider)->get_CanMove(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::CanResize() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider)->get_CanResize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::CanRotate() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider)->get_CanRotate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::Move(double x, double y) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider)->Move(x, y));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::Resize(double width, double height) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider)->Resize(width, height));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider<D>::Rotate(double degrees) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider)->Rotate(degrees));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::CanZoom() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_CanZoom(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::ZoomLevel() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_ZoomLevel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::MaxZoom() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_MaxZoom(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::MinZoom() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->get_MinZoom(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::Zoom(double zoom) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->Zoom(zoom));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_ITransformProvider2<D>::ZoomByUnit(winrt::Windows::UI::Xaml::Automation::ZoomUnit const& zoomUnit) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2)->ZoomByUnit(static_cast<int32_t>(zoomUnit)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IValueProvider<D>::IsReadOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider)->get_IsReadOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Automation_Provider_IValueProvider<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IValueProvider<D>::SetValue(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider)->SetValue(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IVirtualizedItemProvider<D>::Realize() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider)->Realize());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::IsModal() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_IsModal(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::IsTopmost() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_IsTopmost(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::Maximizable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_Maximizable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::Minimizable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_Minimizable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::WindowInteractionState) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::InteractionState() const
    {
        winrt::Windows::UI::Xaml::Automation::WindowInteractionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_InteractionState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Automation::WindowVisualState) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::VisualState() const
    {
        winrt::Windows::UI::Xaml::Automation::WindowVisualState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->get_VisualState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::Close() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->Close());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::SetVisualState(winrt::Windows::UI::Xaml::Automation::WindowVisualState const& state) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->SetVisualState(static_cast<int32_t>(state)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Automation_Provider_IWindowProvider<D>::WaitForInputIdle(int32_t milliseconds) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider)->WaitForInputIdle(milliseconds, &result));
        return result;
    }
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider>
    {
        int32_t __stdcall get_AnnotationTypeId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().AnnotationTypeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AnnotationTypeName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AnnotationTypeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Author(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Author());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DateTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Target(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider>
    {
        int32_t __stdcall NavigateCustom(int32_t direction, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().NavigateCustom(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IDockProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IDockProvider>
    {
        int32_t __stdcall get_DockPosition(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::DockPosition>(this->shim().DockPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDockPosition(int32_t dockPosition) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDockPosition(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::DockPosition const*>(&dockPosition));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider>
    {
        int32_t __stdcall get_IsGrabbed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGrabbed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DropEffect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DropEffect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DropEffects(uint32_t* __valueSize, void*** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            std::tie(*__valueSize, *value) = detach_abi(this->shim().DropEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetGrabbedItems(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetGrabbedItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider>
    {
        int32_t __stdcall get_DropEffect(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DropEffect());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DropEffects(uint32_t* __valueSize, void*** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            std::tie(*__valueSize, *value) = detach_abi(this->shim().DropEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider>
    {
        int32_t __stdcall get_ExpandCollapseState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::ExpandCollapseState>(this->shim().ExpandCollapseState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Collapse() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Collapse();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Expand() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Expand();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider>
    {
        int32_t __stdcall get_Column(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Column());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ColumnSpan(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ColumnSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContainingGrid(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().ContainingGrid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Row(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Row());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RowSpan(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RowSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider>
    {
        int32_t __stdcall get_ColumnCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ColumnCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RowCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RowCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetItem(int32_t row, int32_t column, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().GetItem(row, column));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple>
    {
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider>
    {
        int32_t __stdcall Invoke() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Invoke();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider>
    {
        int32_t __stdcall FindItemByProperty(void* startAfter, void* automationProperty, void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().FindItemByProperty(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&startAfter), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::AutomationProperty const*>(&automationProperty), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider>
    {
        int32_t __stdcall get_CurrentView(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().CurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSupportedViews(uint32_t* __resultSize, int32_t** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetSupportedViews());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetViewName(int32_t viewId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetViewName(viewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetCurrentView(int32_t viewId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetCurrentView(viewId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IObjectModelProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IObjectModelProvider>
    {
        int32_t __stdcall GetUnderlyingObjectModel(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetUnderlyingObjectModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider>
    {
        int32_t __stdcall get_IsReadOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LargeChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().LargeChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Maximum(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Maximum());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Minimum(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Minimum());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SmallChange(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SmallChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetValue(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetValue(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider>
    {
        int32_t __stdcall ScrollIntoView() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScrollIntoView();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider>
    {
        int32_t __stdcall get_HorizontallyScrollable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HorizontallyScrollable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalScrollPercent(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalScrollPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalViewSize(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalViewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticallyScrollable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().VerticallyScrollable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalScrollPercent(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalScrollPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VerticalViewSize(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().VerticalViewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Scroll(int32_t horizontalAmount, int32_t verticalAmount) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Scroll(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::ScrollAmount const*>(&horizontalAmount), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::ScrollAmount const*>(&verticalAmount));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetScrollPercent(double horizontalPercent, double verticalPercent) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetScrollPercent(horizontalPercent, verticalPercent);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider>
    {
        int32_t __stdcall get_IsSelected(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionContainer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().SelectionContainer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToSelection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveFromSelection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveFromSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Select() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Select();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider>
    {
        int32_t __stdcall get_CanSelectMultiple(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSelectMultiple());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSelectionRequired(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSelectionRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSelection(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider>
    {
        int32_t __stdcall get_Formula(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Formula());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnnotationObjects(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetAnnotationObjects());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAnnotationTypes(uint32_t* __resultSize, int32_t** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetAnnotationTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider>
    {
        int32_t __stdcall GetItemByName(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().GetItemByName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider>
    {
        int32_t __stdcall get_ExtendedProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FillColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().FillColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FillPatternColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().FillPatternColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FillPatternStyle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FillPatternStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Shape(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Shape());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StyleId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().StyleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StyleName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().StyleName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider>
    {
        int32_t __stdcall Cancel() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartListening(int32_t inputType) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartListening(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::SynchronizedInputType const*>(&inputType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITableItemProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITableItemProvider>
    {
        int32_t __stdcall GetColumnHeaderItems(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetColumnHeaderItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRowHeaderItems(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetRowHeaderItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider>
    {
        int32_t __stdcall get_RowOrColumnMajor(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::RowOrColumnMajor>(this->shim().RowOrColumnMajor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetColumnHeaders(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetColumnHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRowHeaders(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetRowHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextChildProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextChildProvider>
    {
        int32_t __stdcall get_TextContainer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().TextContainer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextRange(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().TextRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextEditProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextEditProvider>
    {
        int32_t __stdcall GetActiveComposition(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().GetActiveComposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetConversionTarget(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().GetConversionTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider>
    {
        int32_t __stdcall get_DocumentRange(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().DocumentRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedTextSelection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::SupportedTextSelection>(this->shim().SupportedTextSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSelection(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetVisibleRanges(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetVisibleRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RangeFromChild(void* childElement, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().RangeFromChild(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&childElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RangeFromPoint(winrt::Windows::Foundation::Point screenLocation, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().RangeFromPoint(*reinterpret_cast<winrt::Windows::Foundation::Point const*>(&screenLocation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider2> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider2>
    {
        int32_t __stdcall RangeFromAnnotation(void* annotationElement, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().RangeFromAnnotation(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&annotationElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCaretRange(bool* isActive, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().GetCaretRange(*isActive));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>
    {
        int32_t __stdcall Clone(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Compare(void* textRangeProvider, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().Compare(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const*>(&textRangeProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CompareEndpoints(int32_t endpoint, void* textRangeProvider, int32_t targetEndpoint, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().CompareEndpoints(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&endpoint), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const*>(&textRangeProvider), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&targetEndpoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ExpandToEnclosingUnit(int32_t unit) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExpandToEnclosingUnit(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextUnit const*>(&unit));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAttribute(int32_t attributeId, void* value, bool backward, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().FindAttribute(attributeId, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value), backward));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindText(void* text, bool backward, bool ignoreCase, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider>(this->shim().FindText(*reinterpret_cast<hstring const*>(&text), backward, ignoreCase));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAttributeValue(int32_t attributeId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetAttributeValue(attributeId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBoundingRectangles(uint32_t* __returnValueSize, double** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            this->shim().GetBoundingRectangles(detach_abi<double>(__returnValueSize, returnValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEnclosingElement(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().GetEnclosingElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetText(int32_t maxLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetText(maxLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Move(int32_t unit, int32_t count, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().Move(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveEndpointByUnit(int32_t endpoint, int32_t unit, int32_t count, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().MoveEndpointByUnit(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&endpoint), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveEndpointByRange(int32_t endpoint, void* textRangeProvider, int32_t targetEndpoint) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MoveEndpointByRange(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&endpoint), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider const*>(&textRangeProvider), *reinterpret_cast<winrt::Windows::UI::Xaml::Automation::Text::TextPatternRangeEndpoint const*>(&targetEndpoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Select() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Select();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToSelection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveFromSelection() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveFromSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ScrollIntoView(bool alignToTop) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScrollIntoView(alignToTop);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetChildren(uint32_t* __resultSize, void*** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetChildren());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2>
    {
        int32_t __stdcall ShowContextMenu() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowContextMenu();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider>
    {
        int32_t __stdcall get_ToggleState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::ToggleState>(this->shim().ToggleState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Toggle() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Toggle();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider>
    {
        int32_t __stdcall get_CanMove(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanMove());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanResize(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanResize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanRotate(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanRotate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Move(double x, double y) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Move(x, y);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Resize(double width, double height) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resize(width, height);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Rotate(double degrees) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rotate(degrees);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2>
    {
        int32_t __stdcall get_CanZoom(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZoomLevel(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ZoomLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxZoom(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinZoom(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinZoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Zoom(double zoom) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Zoom(zoom);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ZoomByUnit(int32_t zoomUnit) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ZoomByUnit(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::ZoomUnit const*>(&zoomUnit));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider>
    {
        int32_t __stdcall get_IsReadOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetValue(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetValue(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider>
    {
        int32_t __stdcall Realize() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Realize();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider> : produce_base<D, winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider>
    {
        int32_t __stdcall get_IsModal(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsModal());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTopmost(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTopmost());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Maximizable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Maximizable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Minimizable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Minimizable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InteractionState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::WindowInteractionState>(this->shim().InteractionState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VisualState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Automation::WindowVisualState>(this->shim().VisualState());
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
        int32_t __stdcall SetVisualState(int32_t state) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetVisualState(*reinterpret_cast<winrt::Windows::UI::Xaml::Automation::WindowVisualState const*>(&state));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WaitForInputIdle(int32_t milliseconds, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().WaitForInputIdle(milliseconds));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Automation::Provider
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IAnnotationProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ICustomNavigationProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IDockProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IDragProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IDropTargetProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IGridItemProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IGridProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IIRawElementProviderSimple> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IInvokeProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IItemContainerProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IMultipleViewProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IObjectModelProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IRangeValueProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IScrollItemProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IScrollProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISelectionProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetItemProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISpreadsheetProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IStylesProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ISynchronizedInputProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITableItemProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITableProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextChildProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextEditProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextProvider2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITextRangeProvider2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IToggleProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::ITransformProvider2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IValueProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IWindowProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
