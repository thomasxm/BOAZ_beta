// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Interop_1_H
#define WINRT_Windows_UI_Xaml_Interop_1_H
#include "winrt/impl/Windows.UI.Xaml.Interop.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Interop
{
    struct __declspec(empty_bases) IBindableIterable :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindableIterable>
    {
        IBindableIterable(std::nullptr_t = nullptr) noexcept {}
        IBindableIterable(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindableIterator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindableIterator>
    {
        IBindableIterator(std::nullptr_t = nullptr) noexcept {}
        IBindableIterator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}

        using iterator_concept = std::input_iterator_tag;
        using iterator_category = std::input_iterator_tag;
        using value_type = Windows::Foundation::IInspectable;
        using difference_type = ptrdiff_t;
        using pointer = void;
        using reference = Windows::Foundation::IInspectable;
    };
    struct __declspec(empty_bases) IBindableObservableVector :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindableObservableVector>,
        impl::require<winrt::Windows::UI::Xaml::Interop::IBindableObservableVector, winrt::Windows::UI::Xaml::Interop::IBindableIterable, winrt::Windows::UI::Xaml::Interop::IBindableVector>
    {
        IBindableObservableVector(std::nullptr_t = nullptr) noexcept {}
        IBindableObservableVector(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindableVector :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindableVector>,
        impl::require<winrt::Windows::UI::Xaml::Interop::IBindableVector, winrt::Windows::UI::Xaml::Interop::IBindableIterable>
    {
        IBindableVector(std::nullptr_t = nullptr) noexcept {}
        IBindableVector(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IBindableVectorView :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IBindableVectorView>,
        impl::require<winrt::Windows::UI::Xaml::Interop::IBindableVectorView, winrt::Windows::UI::Xaml::Interop::IBindableIterable>
    {
        IBindableVectorView(std::nullptr_t = nullptr) noexcept {}
        IBindableVectorView(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INotifyCollectionChanged :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INotifyCollectionChanged>
    {
        INotifyCollectionChanged(std::nullptr_t = nullptr) noexcept {}
        INotifyCollectionChanged(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INotifyCollectionChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INotifyCollectionChangedEventArgs>
    {
        INotifyCollectionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        INotifyCollectionChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) INotifyCollectionChangedEventArgsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<INotifyCollectionChangedEventArgsFactory>
    {
        INotifyCollectionChangedEventArgsFactory(std::nullptr_t = nullptr) noexcept {}
        INotifyCollectionChangedEventArgsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
