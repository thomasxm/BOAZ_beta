// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Data_1_H
#define WINRT_Windows_UI_Xaml_Data_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.UI.Xaml.Data.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Data
{
    struct __declspec(empty_bases) IBinding :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBinding>
    {
        IBinding(std::nullptr_t = nullptr) noexcept {}
        IBinding(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBinding2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBinding2>
    {
        IBinding2(std::nullptr_t = nullptr) noexcept {}
        IBinding2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingBase :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingBase>
    {
        IBindingBase(std::nullptr_t = nullptr) noexcept {}
        IBindingBase(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingBaseFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingBaseFactory>
    {
        IBindingBaseFactory(std::nullptr_t = nullptr) noexcept {}
        IBindingBaseFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingExpression :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingExpression>
    {
        IBindingExpression(std::nullptr_t = nullptr) noexcept {}
        IBindingExpression(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingExpressionBase :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingExpressionBase>
    {
        IBindingExpressionBase(std::nullptr_t = nullptr) noexcept {}
        IBindingExpressionBase(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingExpressionBaseFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingExpressionBaseFactory>
    {
        IBindingExpressionBaseFactory(std::nullptr_t = nullptr) noexcept {}
        IBindingExpressionBaseFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingExpressionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingExpressionFactory>
    {
        IBindingExpressionFactory(std::nullptr_t = nullptr) noexcept {}
        IBindingExpressionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingFactory>
    {
        IBindingFactory(std::nullptr_t = nullptr) noexcept {}
        IBindingFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingOperations :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingOperations>
    {
        IBindingOperations(std::nullptr_t = nullptr) noexcept {}
        IBindingOperations(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindingOperationsStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindingOperationsStatics>
    {
        IBindingOperationsStatics(std::nullptr_t = nullptr) noexcept {}
        IBindingOperationsStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICollectionView :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICollectionView>,
        impl::require<winrt::Windows::UI::Xaml::Data::ICollectionView, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::IInspectable>, winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::IInspectable>, winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Foundation::IInspectable>>
    {
        ICollectionView(std::nullptr_t = nullptr) noexcept {}
        ICollectionView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICollectionViewFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICollectionViewFactory>
    {
        ICollectionViewFactory(std::nullptr_t = nullptr) noexcept {}
        ICollectionViewFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICollectionViewGroup :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICollectionViewGroup>
    {
        ICollectionViewGroup(std::nullptr_t = nullptr) noexcept {}
        ICollectionViewGroup(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICollectionViewSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICollectionViewSource>
    {
        ICollectionViewSource(std::nullptr_t = nullptr) noexcept {}
        ICollectionViewSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICollectionViewSourceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICollectionViewSourceStatics>
    {
        ICollectionViewSourceStatics(std::nullptr_t = nullptr) noexcept {}
        ICollectionViewSourceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICurrentChangingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICurrentChangingEventArgs>
    {
        ICurrentChangingEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICurrentChangingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICurrentChangingEventArgsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICurrentChangingEventArgsFactory>
    {
        ICurrentChangingEventArgsFactory(std::nullptr_t = nullptr) noexcept {}
        ICurrentChangingEventArgsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomProperty :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomProperty>
    {
        ICustomProperty(std::nullptr_t = nullptr) noexcept {}
        ICustomProperty(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICustomPropertyProvider :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICustomPropertyProvider>
    {
        ICustomPropertyProvider(std::nullptr_t = nullptr) noexcept {}
        ICustomPropertyProvider(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IItemIndexRange :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IItemIndexRange>
    {
        IItemIndexRange(std::nullptr_t = nullptr) noexcept {}
        IItemIndexRange(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IItemIndexRangeFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IItemIndexRangeFactory>
    {
        IItemIndexRangeFactory(std::nullptr_t = nullptr) noexcept {}
        IItemIndexRangeFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IItemsRangeInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IItemsRangeInfo>,
        impl::require<winrt::Windows::UI::Xaml::Data::IItemsRangeInfo, winrt::Windows::Foundation::IClosable>
    {
        IItemsRangeInfo(std::nullptr_t = nullptr) noexcept {}
        IItemsRangeInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INotifyPropertyChanged :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INotifyPropertyChanged>
    {
        INotifyPropertyChanged(std::nullptr_t = nullptr) noexcept {}
        INotifyPropertyChanged(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPropertyChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPropertyChangedEventArgs>
    {
        IPropertyChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPropertyChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPropertyChangedEventArgsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPropertyChangedEventArgsFactory>
    {
        IPropertyChangedEventArgsFactory(std::nullptr_t = nullptr) noexcept {}
        IPropertyChangedEventArgsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRelativeSource :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRelativeSource>
    {
        IRelativeSource(std::nullptr_t = nullptr) noexcept {}
        IRelativeSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IRelativeSourceFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IRelativeSourceFactory>
    {
        IRelativeSourceFactory(std::nullptr_t = nullptr) noexcept {}
        IRelativeSourceFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISelectionInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISelectionInfo>
    {
        ISelectionInfo(std::nullptr_t = nullptr) noexcept {}
        ISelectionInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISupportIncrementalLoading :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISupportIncrementalLoading>
    {
        ISupportIncrementalLoading(std::nullptr_t = nullptr) noexcept {}
        ISupportIncrementalLoading(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IValueConverter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IValueConverter>
    {
        IValueConverter(std::nullptr_t = nullptr) noexcept {}
        IValueConverter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
