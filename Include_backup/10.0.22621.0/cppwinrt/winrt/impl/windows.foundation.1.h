// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Foundation_1_H
#define WINRT_Windows_Foundation_1_H
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct __declspec(empty_bases) IAsyncAction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAsyncAction>,
        impl::require<winrt::Windows::Foundation::IAsyncAction, winrt::Windows::Foundation::IAsyncInfo>
    {
        IAsyncAction(std::nullptr_t = nullptr) noexcept {}
        IAsyncAction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    template <typename TProgress>
    struct __declspec(empty_bases) IAsyncActionWithProgress :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<winrt::Windows::Foundation::IAsyncActionWithProgress<TProgress>>,
        impl::require<winrt::Windows::Foundation::IAsyncActionWithProgress<TProgress>, winrt::Windows::Foundation::IAsyncInfo>
    {
        static_assert(impl::has_category_v<TProgress>, "TProgress must be WinRT type.");
        IAsyncActionWithProgress(std::nullptr_t = nullptr) noexcept {}
        IAsyncActionWithProgress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAsyncInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAsyncInfo>
    {
        IAsyncInfo(std::nullptr_t = nullptr) noexcept {}
        IAsyncInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    template <typename TResult, typename TProgress>
    struct __declspec(empty_bases) IAsyncOperationWithProgress :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<winrt::Windows::Foundation::IAsyncOperationWithProgress<TResult, TProgress>>,
        impl::require<winrt::Windows::Foundation::IAsyncOperationWithProgress<TResult, TProgress>, winrt::Windows::Foundation::IAsyncInfo>
    {
        static_assert(impl::has_category_v<TResult>, "TResult must be WinRT type.");
        static_assert(impl::has_category_v<TProgress>, "TProgress must be WinRT type.");
        IAsyncOperationWithProgress(std::nullptr_t = nullptr) noexcept {}
        IAsyncOperationWithProgress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    template <typename TResult>
    struct __declspec(empty_bases) IAsyncOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<winrt::Windows::Foundation::IAsyncOperation<TResult>>,
        impl::require<winrt::Windows::Foundation::IAsyncOperation<TResult>, winrt::Windows::Foundation::IAsyncInfo>
    {
        static_assert(impl::has_category_v<TResult>, "TResult must be WinRT type.");
        IAsyncOperation(std::nullptr_t = nullptr) noexcept {}
        IAsyncOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IClosable :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IClosable>
    {
        IClosable(std::nullptr_t = nullptr) noexcept {}
        IClosable(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeferral>,
        impl::require<winrt::Windows::Foundation::IDeferral, winrt::Windows::Foundation::IClosable>
    {
        IDeferral(std::nullptr_t = nullptr) noexcept {}
        IDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDeferralFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDeferralFactory>
    {
        IDeferralFactory(std::nullptr_t = nullptr) noexcept {}
        IDeferralFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGetActivationFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGetActivationFactory>
    {
        IGetActivationFactory(std::nullptr_t = nullptr) noexcept {}
        IGetActivationFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGuidHelperStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGuidHelperStatics>
    {
        IGuidHelperStatics(std::nullptr_t = nullptr) noexcept {}
        IGuidHelperStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMemoryBuffer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMemoryBuffer>,
        impl::require<winrt::Windows::Foundation::IMemoryBuffer, winrt::Windows::Foundation::IClosable>
    {
        IMemoryBuffer(std::nullptr_t = nullptr) noexcept {}
        IMemoryBuffer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMemoryBufferFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMemoryBufferFactory>
    {
        IMemoryBufferFactory(std::nullptr_t = nullptr) noexcept {}
        IMemoryBufferFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMemoryBufferReference :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMemoryBufferReference>,
        impl::require<winrt::Windows::Foundation::IMemoryBufferReference, winrt::Windows::Foundation::IClosable>
    {
        IMemoryBufferReference(std::nullptr_t = nullptr) noexcept {}
        IMemoryBufferReference(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPropertyValue :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPropertyValue>
    {
        IPropertyValue(std::nullptr_t = nullptr) noexcept {}
        IPropertyValue(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPropertyValueStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPropertyValueStatics>
    {
        IPropertyValueStatics(std::nullptr_t = nullptr) noexcept {}
        IPropertyValueStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    template <typename T>
    struct __declspec(empty_bases) IReferenceArray :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<winrt::Windows::Foundation::IReferenceArray<T>>,
        impl::require<winrt::Windows::Foundation::IReferenceArray<T>, winrt::Windows::Foundation::IPropertyValue>
    {
        static_assert(impl::has_category_v<T>, "T must be WinRT type.");
        IReferenceArray(std::nullptr_t = nullptr) noexcept {}
        IReferenceArray(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    template <typename T>
    struct __declspec(empty_bases) IReference :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<winrt::Windows::Foundation::IReference<T>>,
        impl::require<winrt::Windows::Foundation::IReference<T>, winrt::Windows::Foundation::IPropertyValue>
    {
        static_assert(impl::has_category_v<T>, "T must be WinRT type.");
        IReference(std::nullptr_t = nullptr) noexcept {}
        IReference(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        IReference(T const& value) : IReference(impl::reference_traits<T>::make(value))
        {
        }
        IReference(std::optional<T> const& value) : IReference(value ? IReference(value.value()) : nullptr)
        {
        }
        operator std::optional<T>() const
        {
            if (*this)
            {
                return this->Value();
            }
            else
            {
                return std::nullopt;
            }
        }
    private:
        IReference(IInspectable const& value) : IReference(value.as<IReference>())
        {
        }
    };
    struct __declspec(empty_bases) IStringable :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStringable>
    {
        IStringable(std::nullptr_t = nullptr) noexcept {}
        IStringable(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUriEscapeStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUriEscapeStatics>
    {
        IUriEscapeStatics(std::nullptr_t = nullptr) noexcept {}
        IUriEscapeStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUriRuntimeClass :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUriRuntimeClass>
    {
        IUriRuntimeClass(std::nullptr_t = nullptr) noexcept {}
        IUriRuntimeClass(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUriRuntimeClassFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUriRuntimeClassFactory>
    {
        IUriRuntimeClassFactory(std::nullptr_t = nullptr) noexcept {}
        IUriRuntimeClassFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IUriRuntimeClassWithAbsoluteCanonicalUri :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IUriRuntimeClassWithAbsoluteCanonicalUri>
    {
        IUriRuntimeClassWithAbsoluteCanonicalUri(std::nullptr_t = nullptr) noexcept {}
        IUriRuntimeClassWithAbsoluteCanonicalUri(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWwwFormUrlDecoderEntry :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWwwFormUrlDecoderEntry>
    {
        IWwwFormUrlDecoderEntry(std::nullptr_t = nullptr) noexcept {}
        IWwwFormUrlDecoderEntry(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWwwFormUrlDecoderRuntimeClass :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWwwFormUrlDecoderRuntimeClass>,
        impl::require<winrt::Windows::Foundation::IWwwFormUrlDecoderRuntimeClass, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::IWwwFormUrlDecoderEntry>, winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::IWwwFormUrlDecoderEntry>>
    {
        IWwwFormUrlDecoderRuntimeClass(std::nullptr_t = nullptr) noexcept {}
        IWwwFormUrlDecoderRuntimeClass(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWwwFormUrlDecoderRuntimeClassFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWwwFormUrlDecoderRuntimeClassFactory>
    {
        IWwwFormUrlDecoderRuntimeClassFactory(std::nullptr_t = nullptr) noexcept {}
        IWwwFormUrlDecoderRuntimeClassFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}

WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T>
    bool operator==(IReference<T> const& left, IReference<T> const& right);

    template <typename T>
    bool operator!=(IReference<T> const& left, IReference<T> const& right);
}

#ifdef __cpp_lib_format
template <>
struct std::formatter<winrt::Windows::Foundation::IStringable, wchar_t> : std::formatter<winrt::hstring, wchar_t>
{
    template <typename FormatContext>
    auto format(winrt::Windows::Foundation::IStringable const& obj, FormatContext& fc);
};
#endif
#endif
