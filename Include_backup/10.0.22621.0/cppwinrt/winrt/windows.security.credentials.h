// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Credentials_H
#define WINRT_Windows_Security_Credentials_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Security_Credentials_ICredentialFactory<D>::CreatePasswordCredential(param::hstring const& resource, param::hstring const& userName, param::hstring const& password) const
    {
        void* credential{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::ICredentialFactory)->CreatePasswordCredential(*(void**)(&resource), *(void**)(&userName), *(void**)(&password), &credential));
        return winrt::Windows::Security::Credentials::PasswordCredential{ credential, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IKeyCredential<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredential)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_Credentials_IKeyCredential<D>::RetrievePublicKey() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredential)->RetrievePublicKeyWithDefaultBlobType(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_Credentials_IKeyCredential<D>::RetrievePublicKey(winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const& blobType) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredential)->RetrievePublicKeyWithBlobType(static_cast<int32_t>(blobType), &value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialOperationResult>) consume_Windows_Security_Credentials_IKeyCredential<D>::RequestSignAsync(winrt::Windows::Storage::Streams::IBuffer const& data) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredential)->RequestSignAsync(*(void**)(&data), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialOperationResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialAttestationResult>) consume_Windows_Security_Credentials_IKeyCredential<D>::GetAttestationAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredential)->GetAttestationAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialAttestationResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_Credentials_IKeyCredentialAttestationResult<D>::CertificateChainBuffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult)->get_CertificateChainBuffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_Credentials_IKeyCredentialAttestationResult<D>::AttestationBuffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult)->get_AttestationBuffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::KeyCredentialAttestationStatus) consume_Windows_Security_Credentials_IKeyCredentialAttestationResult<D>::Status() const
    {
        winrt::Windows::Security::Credentials::KeyCredentialAttestationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::IsSupportedAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics)->IsSupportedAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::RenewAttestationAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics)->RenewAttestationAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult>) consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::RequestCreateAsync(param::hstring const& name, winrt::Windows::Security::Credentials::KeyCredentialCreationOption const& option) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics)->RequestCreateAsync(*(void**)(&name), static_cast<int32_t>(option), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult>) consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::OpenAsync(param::hstring const& name) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics)->OpenAsync(*(void**)(&name), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::DeleteAsync(param::hstring const& name) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics)->DeleteAsync(*(void**)(&name), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_Credentials_IKeyCredentialOperationResult<D>::Result() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialOperationResult)->get_Result(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::KeyCredentialStatus) consume_Windows_Security_Credentials_IKeyCredentialOperationResult<D>::Status() const
    {
        winrt::Windows::Security::Credentials::KeyCredentialStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialOperationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::KeyCredential) consume_Windows_Security_Credentials_IKeyCredentialRetrievalResult<D>::Credential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialRetrievalResult)->get_Credential(&value));
        return winrt::Windows::Security::Credentials::KeyCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::KeyCredentialStatus) consume_Windows_Security_Credentials_IKeyCredentialRetrievalResult<D>::Status() const
    {
        winrt::Windows::Security::Credentials::KeyCredentialStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IKeyCredentialRetrievalResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IPasswordCredential<D>::Resource() const
    {
        void* resource{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->get_Resource(&resource));
        return hstring{ resource, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_IPasswordCredential<D>::Resource(param::hstring const& resource) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->put_Resource(*(void**)(&resource)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IPasswordCredential<D>::UserName() const
    {
        void* userName{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->get_UserName(&userName));
        return hstring{ userName, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_IPasswordCredential<D>::UserName(param::hstring const& userName) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->put_UserName(*(void**)(&userName)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IPasswordCredential<D>::Password() const
    {
        void* password{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->get_Password(&password));
        return hstring{ password, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_IPasswordCredential<D>::Password(param::hstring const& password) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->put_Password(*(void**)(&password)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_IPasswordCredential<D>::RetrievePassword() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->RetrievePassword());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Security_Credentials_IPasswordCredential<D>::Properties() const
    {
        void* props{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordCredential)->get_Properties(&props));
        return winrt::Windows::Foundation::Collections::IPropertySet{ props, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_IPasswordVault<D>::Add(winrt::Windows::Security::Credentials::PasswordCredential const& credential) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordVault)->Add(*(void**)(&credential)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_IPasswordVault<D>::Remove(winrt::Windows::Security::Credentials::PasswordCredential const& credential) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordVault)->Remove(*(void**)(&credential)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Security_Credentials_IPasswordVault<D>::Retrieve(param::hstring const& resource, param::hstring const& userName) const
    {
        void* credential{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordVault)->Retrieve(*(void**)(&resource), *(void**)(&userName), &credential));
        return winrt::Windows::Security::Credentials::PasswordCredential{ credential, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>) consume_Windows_Security_Credentials_IPasswordVault<D>::FindAllByResource(param::hstring const& resource) const
    {
        void* credentials{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordVault)->FindAllByResource(*(void**)(&resource), &credentials));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>{ credentials, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>) consume_Windows_Security_Credentials_IPasswordVault<D>::FindAllByUserName(param::hstring const& userName) const
    {
        void* credentials{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordVault)->FindAllByUserName(*(void**)(&userName), &credentials));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>{ credentials, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>) consume_Windows_Security_Credentials_IPasswordVault<D>::RetrieveAll() const
    {
        void* credentials{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IPasswordVault)->RetrieveAll(&credentials));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>{ credentials, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccountProvider) consume_Windows_Security_Credentials_IWebAccount<D>::WebAccountProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount)->get_WebAccountProvider(&value));
        return winrt::Windows::Security::Credentials::WebAccountProvider{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IWebAccount<D>::UserName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount)->get_UserName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccountState) consume_Windows_Security_Credentials_IWebAccount<D>::State() const
    {
        winrt::Windows::Security::Credentials::WebAccountState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IWebAccount2<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount2)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) consume_Windows_Security_Credentials_IWebAccount2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Security_Credentials_IWebAccount2<D>::GetPictureAsync(winrt::Windows::Security::Credentials::WebAccountPictureSize const& desizedSize) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount2)->GetPictureAsync(static_cast<int32_t>(desizedSize), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Credentials_IWebAccount2<D>::SignOutAsync() const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount2)->SignOutAsync(&asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Security_Credentials_IWebAccount2<D>::SignOutAsync(param::hstring const& clientId) const
    {
        void* asyncInfo{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccount2)->SignOutWithClientIdAsync(*(void**)(&clientId), &asyncInfo));
        return winrt::Windows::Foundation::IAsyncAction{ asyncInfo, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccount) consume_Windows_Security_Credentials_IWebAccountFactory<D>::CreateWebAccount(winrt::Windows::Security::Credentials::WebAccountProvider const& webAccountProvider, param::hstring const& userName, winrt::Windows::Security::Credentials::WebAccountState const& state) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountFactory)->CreateWebAccount(*(void**)(&webAccountProvider), *(void**)(&userName), static_cast<int32_t>(state), &instance));
        return winrt::Windows::Security::Credentials::WebAccount{ instance, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IWebAccountProvider<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProvider)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IWebAccountProvider<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProvider)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Security_Credentials_IWebAccountProvider<D>::IconUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProvider)->get_IconUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IWebAccountProvider2<D>::DisplayPurpose() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProvider2)->get_DisplayPurpose(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_IWebAccountProvider2<D>::Authority() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProvider2)->get_Authority(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::User) consume_Windows_Security_Credentials_IWebAccountProvider3<D>::User() const
    {
        void* user{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProvider3)->get_User(&user));
        return winrt::Windows::System::User{ user, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Credentials_IWebAccountProvider4<D>::IsSystemProvider() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProvider4)->get_IsSystemProvider(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::WebAccountProvider) consume_Windows_Security_Credentials_IWebAccountProviderFactory<D>::CreateWebAccountProvider(param::hstring const& id, param::hstring const& displayName, winrt::Windows::Foundation::Uri const& iconUri) const
    {
        void* instance{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::IWebAccountProviderFactory)->CreateWebAccountProvider(*(void**)(&id), *(void**)(&displayName), *(void**)(&iconUri), &instance));
        return winrt::Windows::Security::Credentials::WebAccountProvider{ instance, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::ICredentialFactory> : produce_base<D, winrt::Windows::Security::Credentials::ICredentialFactory>
    {
        int32_t __stdcall CreatePasswordCredential(void* resource, void* userName, void* password, void** credential) noexcept final try
        {
            clear_abi(credential);
            typename D::abi_guard guard(this->shim());
            *credential = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().CreatePasswordCredential(*reinterpret_cast<hstring const*>(&resource), *reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<hstring const*>(&password)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IKeyCredential> : produce_base<D, winrt::Windows::Security::Credentials::IKeyCredential>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrievePublicKeyWithDefaultBlobType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().RetrievePublicKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrievePublicKeyWithBlobType(int32_t blobType, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().RetrievePublicKey(*reinterpret_cast<winrt::Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const*>(&blobType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestSignAsync(void* data, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialOperationResult>>(this->shim().RequestSignAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAttestationAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialAttestationResult>>(this->shim().GetAttestationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult> : produce_base<D, winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult>
    {
        int32_t __stdcall get_CertificateChainBuffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().CertificateChainBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AttestationBuffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().AttestationBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::KeyCredentialAttestationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics> : produce_base<D, winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics>
    {
        int32_t __stdcall IsSupportedAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSupportedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RenewAttestationAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RenewAttestationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestCreateAsync(void* name, int32_t option, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult>>(this->shim().RequestCreateAsync(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Security::Credentials::KeyCredentialCreationOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenAsync(void* name, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult>>(this->shim().OpenAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteAsync(void* name, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IKeyCredentialOperationResult> : produce_base<D, winrt::Windows::Security::Credentials::IKeyCredentialOperationResult>
    {
        int32_t __stdcall get_Result(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::KeyCredentialStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IKeyCredentialRetrievalResult> : produce_base<D, winrt::Windows::Security::Credentials::IKeyCredentialRetrievalResult>
    {
        int32_t __stdcall get_Credential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::KeyCredential>(this->shim().Credential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::KeyCredentialStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IPasswordCredential> : produce_base<D, winrt::Windows::Security::Credentials::IPasswordCredential>
    {
        int32_t __stdcall get_Resource(void** resource) noexcept final try
        {
            clear_abi(resource);
            typename D::abi_guard guard(this->shim());
            *resource = detach_from<hstring>(this->shim().Resource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Resource(void* resource) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resource(*reinterpret_cast<hstring const*>(&resource));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserName(void** userName) noexcept final try
        {
            clear_abi(userName);
            typename D::abi_guard guard(this->shim());
            *userName = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UserName(void* userName) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UserName(*reinterpret_cast<hstring const*>(&userName));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Password(void** password) noexcept final try
        {
            clear_abi(password);
            typename D::abi_guard guard(this->shim());
            *password = detach_from<hstring>(this->shim().Password());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Password(void* password) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Password(*reinterpret_cast<hstring const*>(&password));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrievePassword() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RetrievePassword();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** props) noexcept final try
        {
            clear_abi(props);
            typename D::abi_guard guard(this->shim());
            *props = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IPasswordVault> : produce_base<D, winrt::Windows::Security::Credentials::IPasswordVault>
    {
        int32_t __stdcall Add(void* credential) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Add(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Remove(void* credential) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Remove(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Retrieve(void* resource, void* userName, void** credential) noexcept final try
        {
            clear_abi(credential);
            typename D::abi_guard guard(this->shim());
            *credential = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().Retrieve(*reinterpret_cast<hstring const*>(&resource), *reinterpret_cast<hstring const*>(&userName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllByResource(void* resource, void** credentials) noexcept final try
        {
            clear_abi(credentials);
            typename D::abi_guard guard(this->shim());
            *credentials = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>>(this->shim().FindAllByResource(*reinterpret_cast<hstring const*>(&resource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllByUserName(void* userName, void** credentials) noexcept final try
        {
            clear_abi(credentials);
            typename D::abi_guard guard(this->shim());
            *credentials = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>>(this->shim().FindAllByUserName(*reinterpret_cast<hstring const*>(&userName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrieveAll(void** credentials) noexcept final try
        {
            clear_abi(credentials);
            typename D::abi_guard guard(this->shim());
            *credentials = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Security::Credentials::PasswordCredential>>(this->shim().RetrieveAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccount> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccount>
    {
        int32_t __stdcall get_WebAccountProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::WebAccountProvider>(this->shim().WebAccountProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UserName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::WebAccountState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccount2> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccount2>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPictureAsync(int32_t desizedSize, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetPictureAsync(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountPictureSize const*>(&desizedSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SignOutAsync(void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SignOutAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SignOutWithClientIdAsync(void* clientId, void** asyncInfo) noexcept final try
        {
            clear_abi(asyncInfo);
            typename D::abi_guard guard(this->shim());
            *asyncInfo = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SignOutAsync(*reinterpret_cast<hstring const*>(&clientId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccountFactory> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccountFactory>
    {
        int32_t __stdcall CreateWebAccount(void* webAccountProvider, void* userName, int32_t state, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Security::Credentials::WebAccount>(this->shim().CreateWebAccount(*reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountProvider const*>(&webAccountProvider), *reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<winrt::Windows::Security::Credentials::WebAccountState const*>(&state)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccountProvider> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccountProvider>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IconUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().IconUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccountProvider2> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccountProvider2>
    {
        int32_t __stdcall get_DisplayPurpose(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayPurpose());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Authority(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Authority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccountProvider3> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccountProvider3>
    {
        int32_t __stdcall get_User(void** user) noexcept final try
        {
            clear_abi(user);
            typename D::abi_guard guard(this->shim());
            *user = detach_from<winrt::Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccountProvider4> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccountProvider4>
    {
        int32_t __stdcall get_IsSystemProvider(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSystemProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::IWebAccountProviderFactory> : produce_base<D, winrt::Windows::Security::Credentials::IWebAccountProviderFactory>
    {
        int32_t __stdcall CreateWebAccountProvider(void* id, void* displayName, void* iconUri, void** instance) noexcept final try
        {
            clear_abi(instance);
            typename D::abi_guard guard(this->shim());
            *instance = detach_from<winrt::Windows::Security::Credentials::WebAccountProvider>(this->shim().CreateWebAccountProvider(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&iconUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Security::Credentials
{
    inline auto KeyCredentialManager::IsSupportedAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<bool>(*)(IKeyCredentialManagerStatics const&), KeyCredentialManager, IKeyCredentialManagerStatics>([](IKeyCredentialManagerStatics const& f) { return f.IsSupportedAsync(); });
    }
    inline auto KeyCredentialManager::RenewAttestationAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncAction(*)(IKeyCredentialManagerStatics const&), KeyCredentialManager, IKeyCredentialManagerStatics>([](IKeyCredentialManagerStatics const& f) { return f.RenewAttestationAsync(); });
    }
    inline auto KeyCredentialManager::RequestCreateAsync(param::hstring const& name, winrt::Windows::Security::Credentials::KeyCredentialCreationOption const& option)
    {
        return impl::call_factory<KeyCredentialManager, IKeyCredentialManagerStatics>([&](IKeyCredentialManagerStatics const& f) { return f.RequestCreateAsync(name, option); });
    }
    inline auto KeyCredentialManager::OpenAsync(param::hstring const& name)
    {
        return impl::call_factory<KeyCredentialManager, IKeyCredentialManagerStatics>([&](IKeyCredentialManagerStatics const& f) { return f.OpenAsync(name); });
    }
    inline auto KeyCredentialManager::DeleteAsync(param::hstring const& name)
    {
        return impl::call_factory<KeyCredentialManager, IKeyCredentialManagerStatics>([&](IKeyCredentialManagerStatics const& f) { return f.DeleteAsync(name); });
    }
    inline PasswordCredential::PasswordCredential() :
        PasswordCredential(impl::call_factory_cast<PasswordCredential(*)(winrt::Windows::Foundation::IActivationFactory const&), PasswordCredential>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PasswordCredential>(); }))
    {
    }
    inline PasswordCredential::PasswordCredential(param::hstring const& resource, param::hstring const& userName, param::hstring const& password) :
        PasswordCredential(impl::call_factory<PasswordCredential, ICredentialFactory>([&](ICredentialFactory const& f) { return f.CreatePasswordCredential(resource, userName, password); }))
    {
    }
    inline PasswordCredentialPropertyStore::PasswordCredentialPropertyStore() :
        PasswordCredentialPropertyStore(impl::call_factory_cast<PasswordCredentialPropertyStore(*)(winrt::Windows::Foundation::IActivationFactory const&), PasswordCredentialPropertyStore>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PasswordCredentialPropertyStore>(); }))
    {
    }
    inline PasswordVault::PasswordVault() :
        PasswordVault(impl::call_factory_cast<PasswordVault(*)(winrt::Windows::Foundation::IActivationFactory const&), PasswordVault>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PasswordVault>(); }))
    {
    }
    inline WebAccount::WebAccount(winrt::Windows::Security::Credentials::WebAccountProvider const& webAccountProvider, param::hstring const& userName, winrt::Windows::Security::Credentials::WebAccountState const& state) :
        WebAccount(impl::call_factory<WebAccount, IWebAccountFactory>([&](IWebAccountFactory const& f) { return f.CreateWebAccount(webAccountProvider, userName, state); }))
    {
    }
    inline WebAccountProvider::WebAccountProvider(param::hstring const& id, param::hstring const& displayName, winrt::Windows::Foundation::Uri const& iconUri) :
        WebAccountProvider(impl::call_factory<WebAccountProvider, IWebAccountProviderFactory>([&](IWebAccountProviderFactory const& f) { return f.CreateWebAccountProvider(id, displayName, iconUri); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Security::Credentials::ICredentialFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredential> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialOperationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialRetrievalResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IPasswordCredential> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IPasswordVault> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccount> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccount2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProviderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::KeyCredential> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialAttestationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialOperationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::PasswordCredential> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::PasswordCredentialPropertyStore> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::PasswordVault> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::WebAccount> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::WebAccountProvider> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
