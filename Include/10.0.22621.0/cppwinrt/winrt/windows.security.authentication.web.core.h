// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Authentication_Web_Core_H
#define WINRT_Windows_Security_Authentication_Web_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Security.Authentication.Web.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::WebAccount>) consume_Windows_Security_Authentication_Web_Core_IFindAllAccountsResult<D>::Accounts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult)->get_Accounts(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::WebAccount>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus) consume_Windows_Security_Authentication_Web_Core_IFindAllAccountsResult<D>::Status() const
    {
        winrt::Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebProviderError) consume_Windows_Security_Authentication_Web_Core_IFindAllAccountsResult<D>::ProviderError() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult)->get_ProviderError(&value));
        return winrt::Windows::Security::Authentication::Web::Core::WebProviderError{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccount) consume_Windows_Security_Authentication_Web_Core_IWebAccountEventArgs<D>::Account() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountEventArgs)->get_Account(&value));
        return winrt::Windows::Security::Credentials::WebAccount{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated_revoker consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->add_Removed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed_revoker consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->remove_Removed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->add_DefaultSignInAccountChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged_revoker consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, DefaultSignInAccountChanged_revoker>(this, DefaultSignInAccountChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->remove_DefaultSignInAccountChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor2<D>::AccountPictureUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor2)->add_AccountPictureUpdated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor2<D>::AccountPictureUpdated_revoker consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor2<D>::AccountPictureUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AccountPictureUpdated_revoker>(this, AccountPictureUpdated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor2<D>::AccountPictureUpdated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor2)->remove_AccountPictureUpdated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::GetTokenSilentlyAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->GetTokenSilentlyAsync(*(void**)(&request), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::GetTokenSilentlyAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::Security::Credentials::WebAccount const& webAccount) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->GetTokenSilentlyWithWebAccountAsync(*(void**)(&request), *(void**)(&webAccount), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::RequestTokenAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->RequestTokenAsync(*(void**)(&request), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::RequestTokenAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::Security::Credentials::WebAccount const& webAccount) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->RequestTokenWithWebAccountAsync(*(void**)(&request), *(void**)(&webAccount), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::FindAccountAsync(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& webAccountId) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->FindAccountAsync(*(void**)(&provider), *(void**)(&webAccountId), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::FindAccountProviderAsync(param::hstring const& webAccountProviderId) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->FindAccountProviderAsync(*(void**)(&webAccountProviderId), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->FindAccountProviderWithAuthorityAsync(*(void**)(&webAccountProviderId), *(void**)(&authority), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics2<D>::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, winrt::Windows::System::User const& user) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2)->FindAccountProviderWithAuthorityForUserAsync(*(void**)(&webAccountProviderId), *(void**)(&authority), *(void**)(&user), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics3<D>::CreateWebAccountMonitor(param::iterable<winrt::Windows::Security::Credentials::WebAccount> const& webAccounts) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3)->CreateWebAccountMonitor(*(void**)(&webAccounts), &result));
        return winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindAllAccountsAsync(winrt::Windows::Security::Credentials::WebAccountProvider const& provider) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindAllAccountsAsync(*(void**)(&provider), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindAllAccountsAsync(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& clientId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindAllAccountsWithClientIdAsync(*(void**)(&provider), *(void**)(&clientId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindSystemAccountProviderAsync(*(void**)(&webAccountProviderId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindSystemAccountProviderWithAuthorityAsync(*(void**)(&webAccountProviderId), *(void**)(&authority), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>) consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, winrt::Windows::System::User const& user) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindSystemAccountProviderWithAuthorityForUserAsync(*(void**)(&webAccountProviderId), *(void**)(&authority), *(void**)(&user), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Security_Authentication_Web_Core_IWebProviderError<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebProviderError)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Authentication_Web_Core_IWebProviderError<D>::ErrorMessage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebProviderError)->get_ErrorMessage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_Security_Authentication_Web_Core_IWebProviderError<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebProviderError)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebProviderError) consume_Windows_Security_Authentication_Web_Core_IWebProviderErrorFactory<D>::Create(uint32_t errorCode, param::hstring const& errorMessage) const
    {
        void* webProviderError{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory)->Create(errorCode, *(void**)(&errorMessage), &webProviderError));
        return winrt::Windows::Security::Authentication::Web::Core::WebProviderError{ webProviderError, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccountProvider) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::WebAccountProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_WebAccountProvider(&value));
        return winrt::Windows::Security::Credentials::WebAccountProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::Scope() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_Scope(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::ClientId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_ClientId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::PromptType() const
    {
        winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_PromptType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::Properties() const
    {
        void* requestProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_Properties(&requestProperties));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ requestProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest2<D>::AppProperties() const
    {
        void* requestProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest2)->get_AppProperties(&requestProperties));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ requestProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest3<D>::CorrelationId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest3)->get_CorrelationId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest3<D>::CorrelationId(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest3)->put_CorrelationId(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::Create(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId) const
    {
        void* webTokenRequest{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->Create(*(void**)(&provider), *(void**)(&scope), *(void**)(&clientId), &webTokenRequest));
        return winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest{ webTokenRequest, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::CreateWithPromptType(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId, winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType const& promptType) const
    {
        void* webTokenRequest{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->CreateWithPromptType(*(void**)(&provider), *(void**)(&scope), *(void**)(&clientId), static_cast<int32_t>(promptType), &webTokenRequest));
        return winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest{ webTokenRequest, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::CreateWithProvider(winrt::Windows::Security::Credentials::WebAccountProvider const& provider) const
    {
        void* webTokenRequest{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->CreateWithProvider(*(void**)(&provider), &webTokenRequest));
        return winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest{ webTokenRequest, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::CreateWithScope(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope) const
    {
        void* webTokenRequest{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->CreateWithScope(*(void**)(&provider), *(void**)(&scope), &webTokenRequest));
        return winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest{ webTokenRequest, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse>) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::ResponseData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->get_ResponseData(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestStatus) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::ResponseStatus() const
    {
        winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->get_ResponseStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebProviderError) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::ResponseError() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->get_ResponseError(&value));
        return winrt::Windows::Security::Authentication::Web::Core::WebProviderError{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::InvalidateCacheAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->InvalidateCacheAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::Token() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_Token(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebProviderError) consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::ProviderError() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_ProviderError(&value));
        return winrt::Windows::Security::Authentication::Web::Core::WebProviderError{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccount) consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::WebAccount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_WebAccount(&value));
        return winrt::Windows::Security::Credentials::WebAccount{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, hstring>) consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMap<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse) consume_Windows_Security_Authentication_Web_Core_IWebTokenResponseFactory<D>::CreateWithToken(param::hstring const& token) const
    {
        void* webTokenResponse{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory)->CreateWithToken(*(void**)(&token), &webTokenResponse));
        return winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse{ webTokenResponse, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse) consume_Windows_Security_Authentication_Web_Core_IWebTokenResponseFactory<D>::CreateWithTokenAndAccount(param::hstring const& token, winrt::Windows::Security::Credentials::WebAccount const& webAccount) const
    {
        void* webTokenResponse{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory)->CreateWithTokenAndAccount(*(void**)(&token), *(void**)(&webAccount), &webTokenResponse));
        return winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse{ webTokenResponse, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse) consume_Windows_Security_Authentication_Web_Core_IWebTokenResponseFactory<D>::CreateWithTokenAccountAndError(param::hstring const& token, winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::Security::Authentication::Web::Core::WebProviderError const& error) const
    {
        void* webTokenResponse{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory)->CreateWithTokenAccountAndError(*(void**)(&token), *(void**)(&webAccount), *(void**)(&error), &webTokenResponse));
        return winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse{ webTokenResponse, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult>
    {
        int32_t __stdcall get_Accounts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::WebAccount>>(this->shim().Accounts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderError(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().ProviderError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebAccountEventArgs> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebAccountEventArgs>
    {
        int32_t __stdcall get_Account(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::WebAccount>(this->shim().Account());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor>
    {
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Removed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Removed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_DefaultSignInAccountChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DefaultSignInAccountChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DefaultSignInAccountChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DefaultSignInAccountChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor2> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor2>
    {
        int32_t __stdcall add_AccountPictureUpdated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AccountPictureUpdated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor, winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AccountPictureUpdated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AccountPictureUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>
    {
        int32_t __stdcall GetTokenSilentlyAsync(void* request, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().GetTokenSilentlyAsync(*reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTokenSilentlyWithWebAccountAsync(void* request, void* webAccount, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().GetTokenSilentlyAsync(*reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestTokenAsync(void* request, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenAsync(*reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestTokenWithWebAccountAsync(void* request, void* webAccount, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenAsync(*reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAccountAsync(void* provider, void* webAccountId, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccount>>(this->shim().FindAccountAsync(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&webAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAccountProviderAsync(void* webAccountProviderId, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAccountProviderWithAuthorityAsync(void* webAccountProviderId, void* authority, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2>
    {
        int32_t __stdcall FindAccountProviderWithAuthorityForUserAsync(void* webAccountProviderId, void* authority, void* user, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority), *reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3>
    {
        int32_t __stdcall CreateWebAccountMonitor(void* webAccounts, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor>(this->shim().CreateWebAccountMonitor(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Security::Credentials::WebAccount> const*>(&webAccounts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4>
    {
        int32_t __stdcall FindAllAccountsAsync(void* provider, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult>>(this->shim().FindAllAccountsAsync(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAccountsWithClientIdAsync(void* provider, void* clientId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult>>(this->shim().FindAllAccountsAsync(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&clientId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindSystemAccountProviderAsync(void* webAccountProviderId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindSystemAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindSystemAccountProviderWithAuthorityAsync(void* webAccountProviderId, void* authority, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindSystemAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindSystemAccountProviderWithAuthorityForUserAsync(void* webAccountProviderId, void* authority, void* user, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindSystemAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority), *reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebProviderError> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebProviderError>
    {
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorMessage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ErrorMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory>
    {
        int32_t __stdcall Create(uint32_t errorCode, void* errorMessage, void** webProviderError) noexcept final try
        {
            clear_abi(webProviderError);
            typename D::abi_guard guard(this->shim());
            *webProviderError = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().Create(errorCode, *reinterpret_cast<hstring const*>(&errorMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest>
    {
        int32_t __stdcall get_WebAccountProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::WebAccountProvider>(this->shim().WebAccountProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scope(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Scope());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ClientId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ClientId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PromptType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType>(this->shim().PromptType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** requestProperties) noexcept final try
        {
            clear_abi(requestProperties);
            typename D::abi_guard guard(this->shim());
            *requestProperties = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest2> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest2>
    {
        int32_t __stdcall get_AppProperties(void** requestProperties) noexcept final try
        {
            clear_abi(requestProperties);
            typename D::abi_guard guard(this->shim());
            *requestProperties = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().AppProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest3> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest3>
    {
        int32_t __stdcall get_CorrelationId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CorrelationId(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CorrelationId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory>
    {
        int32_t __stdcall Create(void* provider, void* scope, void* clientId, void** webTokenRequest) noexcept final try
        {
            clear_abi(webTokenRequest);
            typename D::abi_guard guard(this->shim());
            *webTokenRequest = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().Create(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&scope), *reinterpret_cast<hstring const*>(&clientId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithPromptType(void* provider, void* scope, void* clientId, int32_t promptType, void** webTokenRequest) noexcept final try
        {
            clear_abi(webTokenRequest);
            typename D::abi_guard guard(this->shim());
            *webTokenRequest = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().CreateWithPromptType(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&scope), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType const*>(&promptType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithProvider(void* provider, void** webTokenRequest) noexcept final try
        {
            clear_abi(webTokenRequest);
            typename D::abi_guard guard(this->shim());
            *webTokenRequest = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().CreateWithProvider(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithScope(void* provider, void* scope, void** webTokenRequest) noexcept final try
        {
            clear_abi(webTokenRequest);
            typename D::abi_guard guard(this->shim());
            *webTokenRequest = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().CreateWithScope(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&scope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>
    {
        int32_t __stdcall get_ResponseData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse>>(this->shim().ResponseData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestStatus>(this->shim().ResponseStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResponseError(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().ResponseError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall InvalidateCacheAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().InvalidateCacheAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse>
    {
        int32_t __stdcall get_Token(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Token());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProviderError(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().ProviderError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WebAccount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::WebAccount>(this->shim().WebAccount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory> : produce_base<D, winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory>
    {
        int32_t __stdcall CreateWithToken(void* token, void** webTokenResponse) noexcept final try
        {
            clear_abi(webTokenResponse);
            typename D::abi_guard guard(this->shim());
            *webTokenResponse = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse>(this->shim().CreateWithToken(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTokenAndAccount(void* token, void* webAccount, void** webTokenResponse) noexcept final try
        {
            clear_abi(webTokenResponse);
            typename D::abi_guard guard(this->shim());
            *webTokenResponse = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse>(this->shim().CreateWithTokenAndAccount(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTokenAccountAndError(void* token, void* webAccount, void* error, void** webTokenResponse) noexcept final try
        {
            clear_abi(webTokenResponse);
            typename D::abi_guard guard(this->shim());
            *webTokenResponse = detach_from<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse>(this->shim().CreateWithTokenAccountAndError(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<winrt::Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<winrt::Windows::Security::Authentication::Web::Core::WebProviderError const*>(&error)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web::Core
{
    inline auto WebAuthenticationCoreManager::GetTokenSilentlyAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics>([&](IWebAuthenticationCoreManagerStatics const& f) { return f.GetTokenSilentlyAsync(request); });
    }
    inline auto WebAuthenticationCoreManager::GetTokenSilentlyAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::Security::Credentials::WebAccount const& webAccount)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics>([&](IWebAuthenticationCoreManagerStatics const& f) { return f.GetTokenSilentlyAsync(request, webAccount); });
    }
    inline auto WebAuthenticationCoreManager::RequestTokenAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics>([&](IWebAuthenticationCoreManagerStatics const& f) { return f.RequestTokenAsync(request); });
    }
    inline auto WebAuthenticationCoreManager::RequestTokenAsync(winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, winrt::Windows::Security::Credentials::WebAccount const& webAccount)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics>([&](IWebAuthenticationCoreManagerStatics const& f) { return f.RequestTokenAsync(request, webAccount); });
    }
    inline auto WebAuthenticationCoreManager::FindAccountAsync(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& webAccountId)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics>([&](IWebAuthenticationCoreManagerStatics const& f) { return f.FindAccountAsync(provider, webAccountId); });
    }
    inline auto WebAuthenticationCoreManager::FindAccountProviderAsync(param::hstring const& webAccountProviderId)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics>([&](IWebAuthenticationCoreManagerStatics const& f) { return f.FindAccountProviderAsync(webAccountProviderId); });
    }
    inline auto WebAuthenticationCoreManager::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics>([&](IWebAuthenticationCoreManagerStatics const& f) { return f.FindAccountProviderAsync(webAccountProviderId, authority); });
    }
    inline auto WebAuthenticationCoreManager::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, winrt::Windows::System::User const& user)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics2>([&](IWebAuthenticationCoreManagerStatics2 const& f) { return f.FindAccountProviderAsync(webAccountProviderId, authority, user); });
    }
    inline auto WebAuthenticationCoreManager::CreateWebAccountMonitor(param::iterable<winrt::Windows::Security::Credentials::WebAccount> const& webAccounts)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics3>([&](IWebAuthenticationCoreManagerStatics3 const& f) { return f.CreateWebAccountMonitor(webAccounts); });
    }
    inline auto WebAuthenticationCoreManager::FindAllAccountsAsync(winrt::Windows::Security::Credentials::WebAccountProvider const& provider)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics4>([&](IWebAuthenticationCoreManagerStatics4 const& f) { return f.FindAllAccountsAsync(provider); });
    }
    inline auto WebAuthenticationCoreManager::FindAllAccountsAsync(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& clientId)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics4>([&](IWebAuthenticationCoreManagerStatics4 const& f) { return f.FindAllAccountsAsync(provider, clientId); });
    }
    inline auto WebAuthenticationCoreManager::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics4>([&](IWebAuthenticationCoreManagerStatics4 const& f) { return f.FindSystemAccountProviderAsync(webAccountProviderId); });
    }
    inline auto WebAuthenticationCoreManager::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics4>([&](IWebAuthenticationCoreManagerStatics4 const& f) { return f.FindSystemAccountProviderAsync(webAccountProviderId, authority); });
    }
    inline auto WebAuthenticationCoreManager::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, winrt::Windows::System::User const& user)
    {
        return impl::call_factory<WebAuthenticationCoreManager, IWebAuthenticationCoreManagerStatics4>([&](IWebAuthenticationCoreManagerStatics4 const& f) { return f.FindSystemAccountProviderAsync(webAccountProviderId, authority, user); });
    }
    inline WebProviderError::WebProviderError(uint32_t errorCode, param::hstring const& errorMessage) :
        WebProviderError(impl::call_factory<WebProviderError, IWebProviderErrorFactory>([&](IWebProviderErrorFactory const& f) { return f.Create(errorCode, errorMessage); }))
    {
    }
    inline WebTokenRequest::WebTokenRequest(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId) :
        WebTokenRequest(impl::call_factory<WebTokenRequest, IWebTokenRequestFactory>([&](IWebTokenRequestFactory const& f) { return f.Create(provider, scope, clientId); }))
    {
    }
    inline WebTokenRequest::WebTokenRequest(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId, winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType const& promptType) :
        WebTokenRequest(impl::call_factory<WebTokenRequest, IWebTokenRequestFactory>([&](IWebTokenRequestFactory const& f) { return f.CreateWithPromptType(provider, scope, clientId, promptType); }))
    {
    }
    inline WebTokenRequest::WebTokenRequest(winrt::Windows::Security::Credentials::WebAccountProvider const& provider) :
        WebTokenRequest(impl::call_factory<WebTokenRequest, IWebTokenRequestFactory>([&](IWebTokenRequestFactory const& f) { return f.CreateWithProvider(provider); }))
    {
    }
    inline WebTokenRequest::WebTokenRequest(winrt::Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope) :
        WebTokenRequest(impl::call_factory<WebTokenRequest, IWebTokenRequestFactory>([&](IWebTokenRequestFactory const& f) { return f.CreateWithScope(provider, scope); }))
    {
    }
    inline WebTokenResponse::WebTokenResponse() :
        WebTokenResponse(impl::call_factory_cast<WebTokenResponse(*)(winrt::Windows::Foundation::IActivationFactory const&), WebTokenResponse>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<WebTokenResponse>(); }))
    {
    }
    inline WebTokenResponse::WebTokenResponse(param::hstring const& token) :
        WebTokenResponse(impl::call_factory<WebTokenResponse, IWebTokenResponseFactory>([&](IWebTokenResponseFactory const& f) { return f.CreateWithToken(token); }))
    {
    }
    inline WebTokenResponse::WebTokenResponse(param::hstring const& token, winrt::Windows::Security::Credentials::WebAccount const& webAccount) :
        WebTokenResponse(impl::call_factory<WebTokenResponse, IWebTokenResponseFactory>([&](IWebTokenResponseFactory const& f) { return f.CreateWithTokenAndAccount(token, webAccount); }))
    {
    }
    inline WebTokenResponse::WebTokenResponse(param::hstring const& token, winrt::Windows::Security::Credentials::WebAccount const& webAccount, winrt::Windows::Security::Authentication::Web::Core::WebProviderError const& error) :
        WebTokenResponse(impl::call_factory<WebTokenResponse, IWebTokenResponseFactory>([&](IWebTokenResponseFactory const& f) { return f.CreateWithTokenAccountAndError(token, webAccount, error); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAccountEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebProviderError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebAuthenticationCoreManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebProviderError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
