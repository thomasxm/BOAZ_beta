// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Payments_Provider_H
#define WINRT_Windows_ApplicationModel_Payments_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Payments.h"
#include "winrt/impl/Windows.ApplicationModel.Payments.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.ApplicationModel.Payments.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::PaymentRequest) consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppCanMakePaymentTriggerDetails<D>::Request() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails)->get_Request(&result));
        return winrt::Windows::ApplicationModel::Payments::PaymentRequest{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppCanMakePaymentTriggerDetails<D>::ReportCanMakePaymentResult(winrt::Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails)->ReportCanMakePaymentResult(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManager<D>::RegisterAsync(param::async_iterable<hstring> const& supportedPaymentMethodIds) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager)->RegisterAsync(*(void**)(&supportedPaymentMethodIds), &result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManager<D>::UnregisterAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager)->UnregisterAsync(&result));
        return winrt::Windows::Foundation::IAsyncAction{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager) consume_Windows_ApplicationModel_Payments_Provider_IPaymentAppManagerStatics<D>::Current() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics)->get_Current(&value));
        return winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::PaymentRequest) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PaymentRequest() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PaymentRequest(&value));
        return winrt::Windows::ApplicationModel::Payments::PaymentRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerEmail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PayerEmail(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerEmail(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->put_PayerEmail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PayerName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->put_PayerName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerPhoneNumber() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->get_PayerPhoneNumber(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::PayerPhoneNumber(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->put_PayerPhoneNumber(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::UpdateShippingAddressAsync(winrt::Windows::ApplicationModel::Payments::PaymentAddress const& shippingAddress) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->UpdateShippingAddressAsync(*(void**)(&shippingAddress), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::UpdateSelectedShippingOptionAsync(winrt::Windows::ApplicationModel::Payments::PaymentShippingOption const& selectedShippingOption) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->UpdateSelectedShippingOptionAsync(*(void**)(&selectedShippingOption), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::AcceptAsync(winrt::Windows::ApplicationModel::Payments::PaymentToken const& paymentToken) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->AcceptAsync(*(void**)(&paymentToken), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransaction<D>::Reject() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction)->Reject());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionAcceptResult<D>::Status() const
    {
        winrt::Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction>) consume_Windows_ApplicationModel_Payments_Provider_IPaymentTransactionStatics<D>::FromIdAsync(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics)->FromIdAsync(*(void**)(&id), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails> : produce_base<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails>
    {
        int32_t __stdcall get_Request(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCanMakePaymentResult(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCanMakePaymentResult(*reinterpret_cast<winrt::Windows::ApplicationModel::Payments::PaymentCanMakePaymentResult const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager> : produce_base<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager>
    {
        int32_t __stdcall RegisterAsync(void* supportedPaymentMethodIds, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RegisterAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedPaymentMethodIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UnregisterAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics>
    {
        int32_t __stdcall get_Current(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction> : produce_base<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction>
    {
        int32_t __stdcall get_PaymentRequest(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Payments::PaymentRequest>(this->shim().PaymentRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PayerEmail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PayerEmail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PayerEmail(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PayerEmail(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PayerName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PayerName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PayerName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PayerName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PayerPhoneNumber(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PayerPhoneNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PayerPhoneNumber(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PayerPhoneNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateShippingAddressAsync(void* shippingAddress, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>>(this->shim().UpdateShippingAddressAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Payments::PaymentAddress const*>(&shippingAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdateSelectedShippingOptionAsync(void* selectedShippingOption, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::PaymentRequestChangedResult>>(this->shim().UpdateSelectedShippingOptionAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Payments::PaymentShippingOption const*>(&selectedShippingOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AcceptAsync(void* paymentToken, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult>>(this->shim().AcceptAsync(*reinterpret_cast<winrt::Windows::ApplicationModel::Payments::PaymentToken const*>(&paymentToken)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Reject() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reject();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult> : produce_base<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Payments::PaymentRequestCompletionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics> : produce_base<D, winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics>
    {
        int32_t __stdcall FromIdAsync(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments::Provider
{
    inline auto PaymentAppManager::Current()
    {
        return impl::call_factory_cast<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager(*)(IPaymentAppManagerStatics const&), PaymentAppManager, IPaymentAppManagerStatics>([](IPaymentAppManagerStatics const& f) { return f.Current(); });
    }
    inline auto PaymentTransaction::FromIdAsync(param::hstring const& id)
    {
        return impl::call_factory<PaymentTransaction, IPaymentTransactionStatics>([&](IPaymentTransactionStatics const& f) { return f.FromIdAsync(id); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppCanMakePaymentTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentAppManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransaction> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Payments::Provider::PaymentTransactionAcceptResult> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
