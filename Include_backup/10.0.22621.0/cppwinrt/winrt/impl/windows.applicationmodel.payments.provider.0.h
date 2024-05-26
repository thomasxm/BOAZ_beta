// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Payments_Provider_0_H
#define WINRT_Windows_ApplicationModel_Payments_Provider_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments
{
    struct PaymentAddress;
    struct PaymentCanMakePaymentResult;
    struct PaymentRequest;
    struct PaymentRequestChangedResult;
    enum class PaymentRequestCompletionStatus : int32_t;
    struct PaymentShippingOption;
    struct PaymentToken;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments::Provider
{
    struct IPaymentAppCanMakePaymentTriggerDetails;
    struct IPaymentAppManager;
    struct IPaymentAppManagerStatics;
    struct IPaymentTransaction;
    struct IPaymentTransactionAcceptResult;
    struct IPaymentTransactionStatics;
    struct PaymentAppCanMakePaymentTriggerDetails;
    struct PaymentAppManager;
    struct PaymentTransaction;
    struct PaymentTransactionAcceptResult;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppCanMakePaymentTriggerDetails>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppCanMakePaymentTriggerDetails> = L"Windows.ApplicationModel.Payments.Provider.PaymentAppCanMakePaymentTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager> = L"Windows.ApplicationModel.Payments.Provider.PaymentAppManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction> = L"Windows.ApplicationModel.Payments.Provider.PaymentTransaction";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult> = L"Windows.ApplicationModel.Payments.Provider.PaymentTransactionAcceptResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails> = L"Windows.ApplicationModel.Payments.Provider.IPaymentAppCanMakePaymentTriggerDetails";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager> = L"Windows.ApplicationModel.Payments.Provider.IPaymentAppManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics> = L"Windows.ApplicationModel.Payments.Provider.IPaymentAppManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction> = L"Windows.ApplicationModel.Payments.Provider.IPaymentTransaction";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult> = L"Windows.ApplicationModel.Payments.Provider.IPaymentTransactionAcceptResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics> = L"Windows.ApplicationModel.Payments.Provider.IPaymentTransactionStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails>{ 0x0CE201F0,0x8B93,0x4EB6,{ 0x8C,0x46,0x2E,0x4A,0x6C,0x6A,0x26,0xF6 } }; // 0CE201F0-8B93-4EB6-8C46-2E4A6C6A26F6
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager>{ 0x0E47AA53,0x8521,0x4969,{ 0xA9,0x57,0xDF,0x25,0x38,0xA3,0xA9,0x8F } }; // 0E47AA53-8521-4969-A957-DF2538A3A98F
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics>{ 0xA341AC28,0xFC89,0x4406,{ 0xB4,0xD9,0x34,0xE7,0xFE,0x79,0xDF,0xB6 } }; // A341AC28-FC89-4406-B4D9-34E7FE79DFB6
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction>{ 0x62581DA0,0x26A5,0x4E9B,{ 0xA6,0xEB,0x66,0x60,0x6C,0xF0,0x01,0xD3 } }; // 62581DA0-26A5-4E9B-A6EB-66606CF001D3
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult>{ 0x060E3276,0xD30C,0x4817,{ 0x95,0xA2,0xDF,0x7A,0xE9,0x27,0x3B,0x56 } }; // 060E3276-D30C-4817-95A2-DF7AE9273B56
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics>{ 0x8D639750,0xEE0A,0x4DF5,{ 0x9B,0x1E,0x1C,0x0F,0x9E,0xC5,0x98,0x81 } }; // 8D639750-EE0A-4DF5-9B1E-1C0F9EC59881
    template <> struct default_interface<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppCanMakePaymentTriggerDetails>{ using type = winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager>{ using type = winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction>{ using type = winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>{ using type = winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult; };
    template <> struct abi<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Request(void**) noexcept = 0;
            virtual int32_t __stdcall ReportCanMakePaymentResult(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RegisterAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UnregisterAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Current(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PaymentRequest(void**) noexcept = 0;
            virtual int32_t __stdcall get_PayerEmail(void**) noexcept = 0;
            virtual int32_t __stdcall put_PayerEmail(void*) noexcept = 0;
            virtual int32_t __stdcall get_PayerName(void**) noexcept = 0;
            virtual int32_t __stdcall put_PayerName(void*) noexcept = 0;
            virtual int32_t __stdcall get_PayerPhoneNumber(void**) noexcept = 0;
            virtual int32_t __stdcall put_PayerPhoneNumber(void*) noexcept = 0;
            virtual int32_t __stdcall UpdateShippingAddressAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateSelectedShippingOptionAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AcceptAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall Reject() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppCanMakePaymentTriggerDetails
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::PaymentRequest) Request() const;
        WINRT_IMPL_AUTO(void) ReportCanMakePaymentResult(winrt::Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppCanMakePaymentTriggerDetails<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManager
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) RegisterAsync(param::async_iterable<hstring> const& supportedPaymentMethodIds) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) UnregisterAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManager<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManagerStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager) Current() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::PaymentRequest) PaymentRequest() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PayerEmail() const;
        WINRT_IMPL_AUTO(void) PayerEmail(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PayerName() const;
        WINRT_IMPL_AUTO(void) PayerName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PayerPhoneNumber() const;
        WINRT_IMPL_AUTO(void) PayerPhoneNumber(param::hstring const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>) UpdateShippingAddressAsync(winrt::Windows::ApplicationModel::Payments::PaymentAddress const& shippingAddress) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>) UpdateSelectedShippingOptionAsync(winrt::Windows::ApplicationModel::Payments::PaymentShippingOption const& selectedShippingOption) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>) AcceptAsync(winrt::Windows::ApplicationModel::Payments::PaymentToken const& paymentToken) const;
        WINRT_IMPL_AUTO(void) Reject() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionAcceptResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus) Status() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionAcceptResult<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction>) FromIdAsync(param::hstring const& id) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionStatics<D>;
    };
}
#endif
