// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Data_H
#define WINRT_Windows_UI_Xaml_Data_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.UI.Xaml.Data.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyPath) consume_Windows_UI_Xaml_Data_IBinding<D>::Path() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_Path(&value));
        return winrt::Windows::UI::Xaml::PropertyPath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::Path(winrt::Windows::UI::Xaml::PropertyPath const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_Path(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::BindingMode) consume_Windows_UI_Xaml_Data_IBinding<D>::Mode() const
    {
        winrt::Windows::UI::Xaml::Data::BindingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::Mode(winrt::Windows::UI::Xaml::Data::BindingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_IBinding<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_Source(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::Source(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_Source(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::RelativeSource) consume_Windows_UI_Xaml_Data_IBinding<D>::RelativeSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_RelativeSource(&value));
        return winrt::Windows::UI::Xaml::Data::RelativeSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::RelativeSource(winrt::Windows::UI::Xaml::Data::RelativeSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_RelativeSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Data_IBinding<D>::ElementName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_ElementName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::ElementName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_ElementName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::IValueConverter) consume_Windows_UI_Xaml_Data_IBinding<D>::Converter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_Converter(&value));
        return winrt::Windows::UI::Xaml::Data::IValueConverter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::Converter(winrt::Windows::UI::Xaml::Data::IValueConverter const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_Converter(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterParameter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_ConverterParameter(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterParameter(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_ConverterParameter(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->get_ConverterLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterLanguage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding)->put_ConverterLanguage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_IBinding2<D>::FallbackValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding2)->get_FallbackValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding2<D>::FallbackValue(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding2)->put_FallbackValue(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_IBinding2<D>::TargetNullValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding2)->get_TargetNullValue(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding2<D>::TargetNullValue(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding2)->put_TargetNullValue(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::UpdateSourceTrigger) consume_Windows_UI_Xaml_Data_IBinding2<D>::UpdateSourceTrigger() const
    {
        winrt::Windows::UI::Xaml::Data::UpdateSourceTrigger value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding2)->get_UpdateSourceTrigger(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBinding2<D>::UpdateSourceTrigger(winrt::Windows::UI::Xaml::Data::UpdateSourceTrigger const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBinding2)->put_UpdateSourceTrigger(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::BindingBase) consume_Windows_UI_Xaml_Data_IBindingBaseFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBindingBaseFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Data::BindingBase{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_IBindingExpression<D>::DataItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBindingExpression)->get_DataItem(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::Binding) consume_Windows_UI_Xaml_Data_IBindingExpression<D>::ParentBinding() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBindingExpression)->get_ParentBinding(&value));
        return winrt::Windows::UI::Xaml::Data::Binding{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBindingExpression<D>::UpdateSource() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBindingExpression)->UpdateSource());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::Binding) consume_Windows_UI_Xaml_Data_IBindingFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBindingFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Data::Binding{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IBindingOperationsStatics<D>::SetBinding(winrt::Windows::UI::Xaml::DependencyObject const& target, winrt::Windows::UI::Xaml::DependencyProperty const& dp, winrt::Windows::UI::Xaml::Data::BindingBase const& binding) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IBindingOperationsStatics)->SetBinding(*(void**)(&target), *(void**)(&dp), *(void**)(&binding)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->get_CurrentItem(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentPosition() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->get_CurrentPosition(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::IsCurrentAfterLast() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->get_IsCurrentAfterLast(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::IsCurrentBeforeFirst() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->get_IsCurrentBeforeFirst(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable>) consume_Windows_UI_Xaml_Data_ICollectionView<D>::CollectionGroups() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->get_CollectionGroups(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::HasMoreItems() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->get_HasMoreItems(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->add_CurrentChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged_revoker consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, CurrentChanged_revoker>(this, CurrentChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->remove_CurrentChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging(winrt::Windows::UI::Xaml::Data::CurrentChangingEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->add_CurrentChanging(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging_revoker consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging(auto_revoke_t, winrt::Windows::UI::Xaml::Data::CurrentChangingEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, CurrentChanging_revoker>(this, CurrentChanging(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->remove_CurrentChanging(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentTo(winrt::Windows::Foundation::IInspectable const& item) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentTo(*(void**)(&item), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToPosition(int32_t index) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToPosition(index, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToFirst() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToFirst(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToLast() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToLast(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToNext() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToNext(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToPrevious() const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToPrevious(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Data::LoadMoreItemsResult>) consume_Windows_UI_Xaml_Data_ICollectionView<D>::LoadMoreItemsAsync(uint32_t count) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionView)->LoadMoreItemsAsync(count, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Data::LoadMoreItemsResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::ICollectionView) consume_Windows_UI_Xaml_Data_ICollectionViewFactory<D>::CreateView() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewFactory)->CreateView(&result));
        return winrt::Windows::UI::Xaml::Data::ICollectionView{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_ICollectionViewGroup<D>::Group() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewGroup)->get_Group(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable>) consume_Windows_UI_Xaml_Data_ICollectionViewGroup<D>::GroupItems() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewGroup)->get_GroupItems(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSource)->get_Source(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::Source(winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSource)->put_Source(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::ICollectionView) consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::View() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSource)->get_View(&value));
        return winrt::Windows::UI::Xaml::Data::ICollectionView{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::IsSourceGrouped() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSource)->get_IsSourceGrouped(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::IsSourceGrouped(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSource)->put_IsSourceGrouped(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::PropertyPath) consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::ItemsPath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSource)->get_ItemsPath(&value));
        return winrt::Windows::UI::Xaml::PropertyPath{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::ItemsPath(winrt::Windows::UI::Xaml::PropertyPath const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSource)->put_ItemsPath(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::SourceProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_SourceProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::ViewProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_ViewProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::IsSourceGroupedProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_IsSourceGroupedProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::ItemsPathProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_ItemsPathProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgs<D>::Cancel() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs)->get_Cancel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgs<D>::Cancel(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs)->put_Cancel(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgs<D>::IsCancelable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs)->get_IsCancelable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs) consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgsFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs) consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgsFactory<D>::CreateWithCancelableParameter(bool isCancelable, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory)->CreateWithCancelableParameter(isCancelable, *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Interop::TypeName) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::Type() const
    {
        winrt::Windows::UI::Xaml::Interop::TypeName value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->get_Type(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::GetValue(winrt::Windows::Foundation::IInspectable const& target) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->GetValue(*(void**)(&target), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::SetValue(winrt::Windows::Foundation::IInspectable const& target, winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->SetValue(*(void**)(&target), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::GetIndexedValue(winrt::Windows::Foundation::IInspectable const& target, winrt::Windows::Foundation::IInspectable const& index) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->GetIndexedValue(*(void**)(&target), *(void**)(&index), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::SetIndexedValue(winrt::Windows::Foundation::IInspectable const& target, winrt::Windows::Foundation::IInspectable const& value, winrt::Windows::Foundation::IInspectable const& index) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->SetIndexedValue(*(void**)(&target), *(void**)(&value), *(void**)(&index)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::CanWrite() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->get_CanWrite(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ICustomProperty<D>::CanRead() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomProperty)->get_CanRead(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::ICustomProperty) consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::GetCustomProperty(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider)->GetCustomProperty(*(void**)(&name), &result));
        return winrt::Windows::UI::Xaml::Data::ICustomProperty{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::ICustomProperty) consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::GetIndexedProperty(param::hstring const& name, winrt::Windows::UI::Xaml::Interop::TypeName const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider)->GetIndexedProperty(*(void**)(&name), impl::bind_in(type), &result));
        return winrt::Windows::UI::Xaml::Data::ICustomProperty{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::GetStringRepresentation() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider)->GetStringRepresentation(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Interop::TypeName) consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::Type() const
    {
        winrt::Windows::UI::Xaml::Interop::TypeName value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider)->get_Type(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Data_IItemIndexRange<D>::FirstIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IItemIndexRange)->get_FirstIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_Xaml_Data_IItemIndexRange<D>::Length() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IItemIndexRange)->get_Length(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Data_IItemIndexRange<D>::LastIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IItemIndexRange)->get_LastIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::ItemIndexRange) consume_Windows_UI_Xaml_Data_IItemIndexRangeFactory<D>::CreateInstance(int32_t firstIndex, uint32_t length, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IItemIndexRangeFactory)->CreateInstance(firstIndex, length, *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Data::ItemIndexRange{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IItemsRangeInfo<D>::RangesChanged(winrt::Windows::UI::Xaml::Data::ItemIndexRange const& visibleRange, param::vector_view<winrt::Windows::UI::Xaml::Data::ItemIndexRange> const& trackedItems) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IItemsRangeInfo)->RangesChanged(*(void**)(&visibleRange), *(void**)(&trackedItems)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged(winrt::Windows::UI::Xaml::Data::PropertyChangedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::INotifyPropertyChanged)->add_PropertyChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged_revoker consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged(auto_revoke_t, winrt::Windows::UI::Xaml::Data::PropertyChangedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, PropertyChanged_revoker>(this, PropertyChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::INotifyPropertyChanged)->remove_PropertyChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Data_IPropertyChangedEventArgs<D>::PropertyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgs)->get_PropertyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs) consume_Windows_UI_Xaml_Data_IPropertyChangedEventArgsFactory<D>::CreateInstance(param::hstring const& name, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory)->CreateInstance(*(void**)(&name), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::RelativeSourceMode) consume_Windows_UI_Xaml_Data_IRelativeSource<D>::Mode() const
    {
        winrt::Windows::UI::Xaml::Data::RelativeSourceMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IRelativeSource)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_IRelativeSource<D>::Mode(winrt::Windows::UI::Xaml::Data::RelativeSourceMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IRelativeSource)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Data::RelativeSource) consume_Windows_UI_Xaml_Data_IRelativeSourceFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IRelativeSourceFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Data::RelativeSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::SelectRange(winrt::Windows::UI::Xaml::Data::ItemIndexRange const& itemIndexRange) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ISelectionInfo)->SelectRange(*(void**)(&itemIndexRange)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::DeselectRange(winrt::Windows::UI::Xaml::Data::ItemIndexRange const& itemIndexRange) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ISelectionInfo)->DeselectRange(*(void**)(&itemIndexRange)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::IsSelected(int32_t index) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ISelectionInfo)->IsSelected(index, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Data::ItemIndexRange>) consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::GetSelectedRanges() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ISelectionInfo)->GetSelectedRanges(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Data::ItemIndexRange>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Data::LoadMoreItemsResult>) consume_Windows_UI_Xaml_Data_ISupportIncrementalLoading<D>::LoadMoreItemsAsync(uint32_t count) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ISupportIncrementalLoading)->LoadMoreItemsAsync(count, &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Data::LoadMoreItemsResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Data_ISupportIncrementalLoading<D>::HasMoreItems() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::ISupportIncrementalLoading)->get_HasMoreItems(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_IValueConverter<D>::Convert(winrt::Windows::Foundation::IInspectable const& value, winrt::Windows::UI::Xaml::Interop::TypeName const& targetType, winrt::Windows::Foundation::IInspectable const& parameter, param::hstring const& language) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IValueConverter)->Convert(*(void**)(&value), impl::bind_in(targetType), *(void**)(&parameter), *(void**)(&language), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Data_IValueConverter<D>::ConvertBack(winrt::Windows::Foundation::IInspectable const& value, winrt::Windows::UI::Xaml::Interop::TypeName const& targetType, winrt::Windows::Foundation::IInspectable const& parameter, param::hstring const& language) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Data::IValueConverter)->ConvertBack(*(void**)(&value), impl::bind_in(targetType), *(void**)(&parameter), *(void**)(&language), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Data::CurrentChangingEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Data::CurrentChangingEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Data::CurrentChangingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Data::PropertyChangedEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Data::PropertyChangedEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Data::PropertyChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBinding> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBinding>
    {
        int32_t __stdcall get_Path(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::PropertyPath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Path(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Path(*reinterpret_cast<winrt::Windows::UI::Xaml::PropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::BindingMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::BindingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Source(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Source(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RelativeSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::RelativeSource>(this->shim().RelativeSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RelativeSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RelativeSource(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::RelativeSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ElementName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ElementName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ElementName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Converter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::IValueConverter>(this->shim().Converter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Converter(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Converter(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::IValueConverter const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConverterParameter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ConverterParameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ConverterParameter(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConverterParameter(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConverterLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ConverterLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ConverterLanguage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConverterLanguage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBinding2> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBinding2>
    {
        int32_t __stdcall get_FallbackValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().FallbackValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FallbackValue(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FallbackValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetNullValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().TargetNullValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetNullValue(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetNullValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UpdateSourceTrigger(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::UpdateSourceTrigger>(this->shim().UpdateSourceTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UpdateSourceTrigger(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateSourceTrigger(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::UpdateSourceTrigger const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingBase> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingBase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingBaseFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::BindingBase>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingExpression> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingExpression>
    {
        int32_t __stdcall get_DataItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().DataItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ParentBinding(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::Binding>(this->shim().ParentBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateSource() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateSource();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingExpressionBase> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingExpressionBase>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingExpressionBaseFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingExpressionBaseFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingExpressionFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingExpressionFactory>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::Binding>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingOperations> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingOperations>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IBindingOperationsStatics> : produce_base<D, winrt::Windows::UI::Xaml::Data::IBindingOperationsStatics>
    {
        int32_t __stdcall SetBinding(void* target, void* dp, void* binding) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBinding(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&target), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<winrt::Windows::UI::Xaml::Data::BindingBase const*>(&binding));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICollectionView> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICollectionView>
    {
        int32_t __stdcall get_CurrentItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().CurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentPosition(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().CurrentPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCurrentAfterLast(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCurrentAfterLast());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCurrentBeforeFirst(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCurrentBeforeFirst());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CollectionGroups(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable>>(this->shim().CollectionGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasMoreItems(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasMoreItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CurrentChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CurrentChanging(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CurrentChanging(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::CurrentChangingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CurrentChanging(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CurrentChanging(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall MoveCurrentTo(void* item, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().MoveCurrentTo(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveCurrentToPosition(int32_t index, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().MoveCurrentToPosition(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveCurrentToFirst(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().MoveCurrentToFirst());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveCurrentToLast(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().MoveCurrentToLast());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveCurrentToNext(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().MoveCurrentToNext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MoveCurrentToPrevious(bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().MoveCurrentToPrevious());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadMoreItemsAsync(uint32_t count, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Data::LoadMoreItemsResult>>(this->shim().LoadMoreItemsAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICollectionViewFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICollectionViewFactory>
    {
        int32_t __stdcall CreateView(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Data::ICollectionView>(this->shim().CreateView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICollectionViewGroup> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICollectionViewGroup>
    {
        int32_t __stdcall get_Group(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GroupItems(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable>>(this->shim().GroupItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICollectionViewSource> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICollectionViewSource>
    {
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Source(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Source(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_View(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::ICollectionView>(this->shim().View());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSourceGrouped(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSourceGrouped());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsSourceGrouped(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsSourceGrouped(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemsPath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::PropertyPath>(this->shim().ItemsPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ItemsPath(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ItemsPath(*reinterpret_cast<winrt::Windows::UI::Xaml::PropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics>
    {
        int32_t __stdcall get_SourceProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().SourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ViewProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSourceGroupedProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsSourceGroupedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemsPathProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().ItemsPathProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs>
    {
        int32_t __stdcall get_Cancel(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Cancel(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCancelable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCancelable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithCancelableParameter(bool isCancelable, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs>(this->shim().CreateWithCancelableParameter(isCancelable, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICustomProperty> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICustomProperty>
    {
        int32_t __stdcall get_Type(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Interop::TypeName>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Interop::TypeName>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetValue(void* target, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetValue(void* target, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIndexedValue(void* target, void* index, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetIndexedValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&index)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetIndexedValue(void* target, void* value, void* index) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetIndexedValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&target), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanWrite(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanWrite());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanRead(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider> : produce_base<D, winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider>
    {
        int32_t __stdcall GetCustomProperty(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Data::ICustomProperty>(this->shim().GetCustomProperty(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIndexedProperty(void* name, struct struct_Windows_UI_Xaml_Interop_TypeName type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Data::ICustomProperty>(this->shim().GetIndexedProperty(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStringRepresentation(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetStringRepresentation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Interop::TypeName>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Interop::TypeName>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IItemIndexRange> : produce_base<D, winrt::Windows::UI::Xaml::Data::IItemIndexRange>
    {
        int32_t __stdcall get_FirstIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Length(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IItemIndexRangeFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::IItemIndexRangeFactory>
    {
        int32_t __stdcall CreateInstance(int32_t firstIndex, uint32_t length, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::ItemIndexRange>(this->shim().CreateInstance(firstIndex, length, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IItemsRangeInfo> : produce_base<D, winrt::Windows::UI::Xaml::Data::IItemsRangeInfo>
    {
        int32_t __stdcall RangesChanged(void* visibleRange, void* trackedItems) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RangesChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::ItemIndexRange const*>(&visibleRange), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Data::ItemIndexRange> const*>(&trackedItems));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::INotifyPropertyChanged> : produce_base<D, winrt::Windows::UI::Xaml::Data::INotifyPropertyChanged>
    {
        int32_t __stdcall add_PropertyChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PropertyChanged(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::PropertyChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PropertyChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PropertyChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgs>
    {
        int32_t __stdcall get_PropertyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PropertyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory>
    {
        int32_t __stdcall CreateInstance(void* name, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IRelativeSource> : produce_base<D, winrt::Windows::UI::Xaml::Data::IRelativeSource>
    {
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::RelativeSourceMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::RelativeSourceMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IRelativeSourceFactory> : produce_base<D, winrt::Windows::UI::Xaml::Data::IRelativeSourceFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Data::RelativeSource>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ISelectionInfo> : produce_base<D, winrt::Windows::UI::Xaml::Data::ISelectionInfo>
    {
        int32_t __stdcall SelectRange(void* itemIndexRange) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectRange(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::ItemIndexRange const*>(&itemIndexRange));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeselectRange(void* itemIndexRange) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeselectRange(*reinterpret_cast<winrt::Windows::UI::Xaml::Data::ItemIndexRange const*>(&itemIndexRange));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSelected(int32_t index, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSelected(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSelectedRanges(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Xaml::Data::ItemIndexRange>>(this->shim().GetSelectedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::ISupportIncrementalLoading> : produce_base<D, winrt::Windows::UI::Xaml::Data::ISupportIncrementalLoading>
    {
        int32_t __stdcall LoadMoreItemsAsync(uint32_t count, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Data::LoadMoreItemsResult>>(this->shim().LoadMoreItemsAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HasMoreItems(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().HasMoreItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Data::IValueConverter> : produce_base<D, winrt::Windows::UI::Xaml::Data::IValueConverter>
    {
        int32_t __stdcall Convert(void* value, struct struct_Windows_UI_Xaml_Interop_TypeName targetType, void* parameter, void* language, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Convert(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&targetType), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&parameter), *reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertBack(void* value, struct struct_Windows_UI_Xaml_Interop_TypeName targetType, void* parameter, void* language, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ConvertBack(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&targetType), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&parameter), *reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Data
{
    inline Binding::Binding()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<Binding, IBindingFactory>([&](IBindingFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline BindingBase::BindingBase()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<BindingBase, IBindingBaseFactory>([&](IBindingBaseFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto BindingOperations::SetBinding(winrt::Windows::UI::Xaml::DependencyObject const& target, winrt::Windows::UI::Xaml::DependencyProperty const& dp, winrt::Windows::UI::Xaml::Data::BindingBase const& binding)
    {
        impl::call_factory<BindingOperations, IBindingOperationsStatics>([&](IBindingOperationsStatics const& f) { return f.SetBinding(target, dp, binding); });
    }
    inline CollectionViewSource::CollectionViewSource() :
        CollectionViewSource(impl::call_factory_cast<CollectionViewSource(*)(winrt::Windows::Foundation::IActivationFactory const&), CollectionViewSource>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CollectionViewSource>(); }))
    {
    }
    inline auto CollectionViewSource::SourceProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICollectionViewSourceStatics const&), CollectionViewSource, ICollectionViewSourceStatics>([](ICollectionViewSourceStatics const& f) { return f.SourceProperty(); });
    }
    inline auto CollectionViewSource::ViewProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICollectionViewSourceStatics const&), CollectionViewSource, ICollectionViewSourceStatics>([](ICollectionViewSourceStatics const& f) { return f.ViewProperty(); });
    }
    inline auto CollectionViewSource::IsSourceGroupedProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICollectionViewSourceStatics const&), CollectionViewSource, ICollectionViewSourceStatics>([](ICollectionViewSourceStatics const& f) { return f.IsSourceGroupedProperty(); });
    }
    inline auto CollectionViewSource::ItemsPathProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ICollectionViewSourceStatics const&), CollectionViewSource, ICollectionViewSourceStatics>([](ICollectionViewSourceStatics const& f) { return f.ItemsPathProperty(); });
    }
    inline CurrentChangingEventArgs::CurrentChangingEventArgs()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<CurrentChangingEventArgs, ICurrentChangingEventArgsFactory>([&](ICurrentChangingEventArgsFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline CurrentChangingEventArgs::CurrentChangingEventArgs(bool isCancelable)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<CurrentChangingEventArgs, ICurrentChangingEventArgsFactory>([&](ICurrentChangingEventArgsFactory const& f) { return f.CreateWithCancelableParameter(isCancelable, baseInterface, innerInterface); });
    }
    inline ItemIndexRange::ItemIndexRange(int32_t firstIndex, uint32_t length)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<ItemIndexRange, IItemIndexRangeFactory>([&](IItemIndexRangeFactory const& f) { return f.CreateInstance(firstIndex, length, baseInterface, innerInterface); });
    }
    inline PropertyChangedEventArgs::PropertyChangedEventArgs(param::hstring const& name)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<PropertyChangedEventArgs, IPropertyChangedEventArgsFactory>([&](IPropertyChangedEventArgsFactory const& f) { return f.CreateInstance(name, baseInterface, innerInterface); });
    }
    inline RelativeSource::RelativeSource()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<RelativeSource, IRelativeSourceFactory>([&](IRelativeSourceFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    template <typename L> CurrentChangingEventHandler::CurrentChangingEventHandler(L handler) :
        CurrentChangingEventHandler(impl::make_delegate<CurrentChangingEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> CurrentChangingEventHandler::CurrentChangingEventHandler(F* handler) :
        CurrentChangingEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> CurrentChangingEventHandler::CurrentChangingEventHandler(O* object, M method) :
        CurrentChangingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> CurrentChangingEventHandler::CurrentChangingEventHandler(com_ptr<O>&& object, M method) :
        CurrentChangingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> CurrentChangingEventHandler::CurrentChangingEventHandler(weak_ref<O>&& object, M method) :
        CurrentChangingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto CurrentChangingEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<CurrentChangingEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename L> PropertyChangedEventHandler::PropertyChangedEventHandler(L handler) :
        PropertyChangedEventHandler(impl::make_delegate<PropertyChangedEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> PropertyChangedEventHandler::PropertyChangedEventHandler(F* handler) :
        PropertyChangedEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> PropertyChangedEventHandler::PropertyChangedEventHandler(O* object, M method) :
        PropertyChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> PropertyChangedEventHandler::PropertyChangedEventHandler(com_ptr<O>&& object, M method) :
        PropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> PropertyChangedEventHandler::PropertyChangedEventHandler(weak_ref<O>&& object, M method) :
        PropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto PropertyChangedEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<PropertyChangedEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename D, typename... Interfaces>
    struct BindingT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Data::IBinding, winrt::Windows::UI::Xaml::Data::IBinding2, winrt::Windows::UI::Xaml::Data::IBindingBase, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, Binding, winrt::Windows::UI::Xaml::Data::BindingBase, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = Binding;
    protected:
        BindingT()
        {
            impl::call_factory<Binding, IBindingFactory>([&](IBindingFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct BindingBaseT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Data::IBindingBase, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, BindingBase, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = BindingBase;
    protected:
        BindingBaseT()
        {
            impl::call_factory<BindingBase, IBindingBaseFactory>([&](IBindingBaseFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct CurrentChangingEventArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs>,
        impl::base<D, CurrentChangingEventArgs>
    {
        using composable = CurrentChangingEventArgs;
    protected:
        CurrentChangingEventArgsT()
        {
            impl::call_factory<CurrentChangingEventArgs, ICurrentChangingEventArgsFactory>([&](ICurrentChangingEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
        CurrentChangingEventArgsT(bool isCancelable)
        {
            impl::call_factory<CurrentChangingEventArgs, ICurrentChangingEventArgsFactory>([&](ICurrentChangingEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateWithCancelableParameter(isCancelable, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct ItemIndexRangeT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Data::IItemIndexRange>,
        impl::base<D, ItemIndexRange>
    {
        using composable = ItemIndexRange;
    protected:
        ItemIndexRangeT(int32_t firstIndex, uint32_t length)
        {
            impl::call_factory<ItemIndexRange, IItemIndexRangeFactory>([&](IItemIndexRangeFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(firstIndex, length, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct PropertyChangedEventArgsT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgs>,
        impl::base<D, PropertyChangedEventArgs>
    {
        using composable = PropertyChangedEventArgs;
    protected:
        PropertyChangedEventArgsT(param::hstring const& name)
        {
            impl::call_factory<PropertyChangedEventArgs, IPropertyChangedEventArgsFactory>([&](IPropertyChangedEventArgsFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(name, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct RelativeSourceT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Data::IRelativeSource, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, RelativeSource, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = RelativeSource;
    protected:
        RelativeSourceT()
        {
            impl::call_factory<RelativeSource, IRelativeSourceFactory>([&](IRelativeSourceFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBinding> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBinding2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpression> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpressionBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpressionBaseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpressionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingOperations> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingOperationsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionView> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICustomProperty> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IItemIndexRange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IItemIndexRangeFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IItemsRangeInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::INotifyPropertyChanged> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IRelativeSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IRelativeSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ISelectionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ISupportIncrementalLoading> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::IValueConverter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::Binding> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingExpression> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingExpressionBase> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingOperations> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::CollectionViewSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::ItemIndexRange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Data::RelativeSource> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
