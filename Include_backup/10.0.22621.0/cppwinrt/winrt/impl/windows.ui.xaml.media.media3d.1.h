// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Media_Media3D_1_H
#define WINRT_Windows_UI_Xaml_Media_Media3D_1_H
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.0.h"
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Media3D
{
    struct __declspec(empty_bases) ICompositeTransform3D :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICompositeTransform3D>
    {
        ICompositeTransform3D(std::nullptr_t = nullptr) noexcept {}
        ICompositeTransform3D(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICompositeTransform3DStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICompositeTransform3DStatics>
    {
        ICompositeTransform3DStatics(std::nullptr_t = nullptr) noexcept {}
        ICompositeTransform3DStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMatrix3DHelper :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMatrix3DHelper>
    {
        IMatrix3DHelper(std::nullptr_t = nullptr) noexcept {}
        IMatrix3DHelper(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMatrix3DHelperStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMatrix3DHelperStatics>
    {
        IMatrix3DHelperStatics(std::nullptr_t = nullptr) noexcept {}
        IMatrix3DHelperStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerspectiveTransform3D :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerspectiveTransform3D>
    {
        IPerspectiveTransform3D(std::nullptr_t = nullptr) noexcept {}
        IPerspectiveTransform3D(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPerspectiveTransform3DStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPerspectiveTransform3DStatics>
    {
        IPerspectiveTransform3DStatics(std::nullptr_t = nullptr) noexcept {}
        IPerspectiveTransform3DStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITransform3D :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITransform3D>
    {
        ITransform3D(std::nullptr_t = nullptr) noexcept {}
        ITransform3D(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITransform3DFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITransform3DFactory>
    {
        ITransform3DFactory(std::nullptr_t = nullptr) noexcept {}
        ITransform3DFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
