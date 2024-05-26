// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Payments_1_H
#define WINRT_Windows_ApplicationModel_Payments_1_H
#include "winrt/impl/Windows.ApplicationModel.Payments.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments
{
    struct __declspec(empty_bases) IPaymentAddress :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentAddress>
    {
        IPaymentAddress(std::nullptr_t = nullptr) noexcept {}
        IPaymentAddress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentCanMakePaymentResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentCanMakePaymentResult>
    {
        IPaymentCanMakePaymentResult(std::nullptr_t = nullptr) noexcept {}
        IPaymentCanMakePaymentResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentCanMakePaymentResultFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentCanMakePaymentResultFactory>
    {
        IPaymentCanMakePaymentResultFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentCanMakePaymentResultFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentCurrencyAmount :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentCurrencyAmount>
    {
        IPaymentCurrencyAmount(std::nullptr_t = nullptr) noexcept {}
        IPaymentCurrencyAmount(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentCurrencyAmountFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentCurrencyAmountFactory>
    {
        IPaymentCurrencyAmountFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentCurrencyAmountFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentDetails>
    {
        IPaymentDetails(std::nullptr_t = nullptr) noexcept {}
        IPaymentDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentDetailsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentDetailsFactory>
    {
        IPaymentDetailsFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentDetailsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentDetailsModifier :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentDetailsModifier>
    {
        IPaymentDetailsModifier(std::nullptr_t = nullptr) noexcept {}
        IPaymentDetailsModifier(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentDetailsModifierFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentDetailsModifierFactory>
    {
        IPaymentDetailsModifierFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentDetailsModifierFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentItem>
    {
        IPaymentItem(std::nullptr_t = nullptr) noexcept {}
        IPaymentItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentItemFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentItemFactory>
    {
        IPaymentItemFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentItemFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentMediator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentMediator>
    {
        IPaymentMediator(std::nullptr_t = nullptr) noexcept {}
        IPaymentMediator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentMediator2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentMediator2>
    {
        IPaymentMediator2(std::nullptr_t = nullptr) noexcept {}
        IPaymentMediator2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentMerchantInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentMerchantInfo>
    {
        IPaymentMerchantInfo(std::nullptr_t = nullptr) noexcept {}
        IPaymentMerchantInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentMerchantInfoFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentMerchantInfoFactory>
    {
        IPaymentMerchantInfoFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentMerchantInfoFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentMethodData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentMethodData>
    {
        IPaymentMethodData(std::nullptr_t = nullptr) noexcept {}
        IPaymentMethodData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentMethodDataFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentMethodDataFactory>
    {
        IPaymentMethodDataFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentMethodDataFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentOptions>
    {
        IPaymentOptions(std::nullptr_t = nullptr) noexcept {}
        IPaymentOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequest>
    {
        IPaymentRequest(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequest2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequest2>
    {
        IPaymentRequest2(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequest2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequestChangedArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequestChangedArgs>
    {
        IPaymentRequestChangedArgs(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequestChangedArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequestChangedResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequestChangedResult>
    {
        IPaymentRequestChangedResult(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequestChangedResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequestChangedResultFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequestChangedResultFactory>
    {
        IPaymentRequestChangedResultFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequestChangedResultFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequestFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequestFactory>
    {
        IPaymentRequestFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequestFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequestFactory2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequestFactory2>
    {
        IPaymentRequestFactory2(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequestFactory2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentRequestSubmitResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentRequestSubmitResult>
    {
        IPaymentRequestSubmitResult(std::nullptr_t = nullptr) noexcept {}
        IPaymentRequestSubmitResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentResponse :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentResponse>
    {
        IPaymentResponse(std::nullptr_t = nullptr) noexcept {}
        IPaymentResponse(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentShippingOption :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentShippingOption>
    {
        IPaymentShippingOption(std::nullptr_t = nullptr) noexcept {}
        IPaymentShippingOption(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentShippingOptionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentShippingOptionFactory>
    {
        IPaymentShippingOptionFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentShippingOptionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentToken :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentToken>
    {
        IPaymentToken(std::nullptr_t = nullptr) noexcept {}
        IPaymentToken(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentTokenFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentTokenFactory>
    {
        IPaymentTokenFactory(std::nullptr_t = nullptr) noexcept {}
        IPaymentTokenFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
