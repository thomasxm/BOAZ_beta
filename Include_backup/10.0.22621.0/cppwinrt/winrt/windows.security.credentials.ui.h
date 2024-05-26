// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Credentials_UI_H
#define WINRT_Windows_Security_Credentials_UI_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Security.Credentials.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Security.Credentials.UI.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Caption(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_Caption(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Caption() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_Caption(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Message(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_Message(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_Message(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::ErrorCode(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_ErrorCode(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::TargetName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_TargetName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::TargetName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_TargetName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AuthenticationProtocol(winrt::Windows::Security::Credentials::UI::AuthenticationProtocol const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_AuthenticationProtocol(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::UI::AuthenticationProtocol) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AuthenticationProtocol() const
    {
        winrt::Windows::Security::Credentials::UI::AuthenticationProtocol value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_AuthenticationProtocol(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CustomAuthenticationProtocol(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_CustomAuthenticationProtocol(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CustomAuthenticationProtocol() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_CustomAuthenticationProtocol(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::PreviousCredential(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_PreviousCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::PreviousCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_PreviousCredential(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AlwaysDisplayDialog(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_AlwaysDisplayDialog(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AlwaysDisplayDialog() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_AlwaysDisplayDialog(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CallerSavesCredential(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_CallerSavesCredential(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CallerSavesCredential() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_CallerSavesCredential(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CredentialSaveOption(winrt::Windows::Security::Credentials::UI::CredentialSaveOption const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_CredentialSaveOption(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::UI::CredentialSaveOption) consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CredentialSaveOption() const
    {
        winrt::Windows::Security::Credentials::UI::CredentialSaveOption value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_CredentialSaveOption(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::ErrorCode() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerResults)->get_ErrorCode(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::UI::CredentialSaveOption) consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialSaveOption() const
    {
        winrt::Windows::Security::Credentials::UI::CredentialSaveOption value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialSaveOption(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialSaved() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialSaved(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::Credential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerResults)->get_Credential(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialDomainName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialDomainName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialUserName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialUserName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialPassword() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialPassword(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>) consume_Windows_Security_Credentials_UI_ICredentialPickerStatics<D>::PickAsync(winrt::Windows::Security::Credentials::UI::CredentialPickerOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics)->PickWithOptionsAsync(*(void**)(&options), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>) consume_Windows_Security_Credentials_UI_ICredentialPickerStatics<D>::PickAsync(param::hstring const& targetName, param::hstring const& message) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics)->PickWithMessageAsync(*(void**)(&targetName), *(void**)(&message), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>) consume_Windows_Security_Credentials_UI_ICredentialPickerStatics<D>::PickAsync(param::hstring const& targetName, param::hstring const& message, param::hstring const& caption) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics)->PickWithCaptionAsync(*(void**)(&targetName), *(void**)(&message), *(void**)(&caption), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::UserConsentVerifierAvailability>) consume_Windows_Security_Credentials_UI_IUserConsentVerifierStatics<D>::CheckAvailabilityAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::IUserConsentVerifierStatics)->CheckAvailabilityAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::UserConsentVerifierAvailability>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::UserConsentVerificationResult>) consume_Windows_Security_Credentials_UI_IUserConsentVerifierStatics<D>::RequestVerificationAsync(param::hstring const& message) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Security::Credentials::UI::IUserConsentVerifierStatics)->RequestVerificationAsync(*(void**)(&message), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::UserConsentVerificationResult>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions> : produce_base<D, winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions>
    {
        int32_t __stdcall put_Caption(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Caption(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Caption(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Message(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Message(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ErrorCode(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ErrorCode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TargetName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AuthenticationProtocol(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AuthenticationProtocol(*reinterpret_cast<winrt::Windows::Security::Credentials::UI::AuthenticationProtocol const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AuthenticationProtocol(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::UI::AuthenticationProtocol>(this->shim().AuthenticationProtocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CustomAuthenticationProtocol(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CustomAuthenticationProtocol(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CustomAuthenticationProtocol(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CustomAuthenticationProtocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PreviousCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PreviousCredential(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreviousCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().PreviousCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AlwaysDisplayDialog(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AlwaysDisplayDialog(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AlwaysDisplayDialog(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AlwaysDisplayDialog());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CallerSavesCredential(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CallerSavesCredential(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CallerSavesCredential(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CallerSavesCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CredentialSaveOption(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CredentialSaveOption(*reinterpret_cast<winrt::Windows::Security::Credentials::UI::CredentialSaveOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CredentialSaveOption(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::UI::CredentialSaveOption>(this->shim().CredentialSaveOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::UI::ICredentialPickerResults> : produce_base<D, winrt::Windows::Security::Credentials::UI::ICredentialPickerResults>
    {
        int32_t __stdcall get_ErrorCode(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CredentialSaveOption(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::UI::CredentialSaveOption>(this->shim().CredentialSaveOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CredentialSaved(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CredentialSaved());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Credential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Credential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CredentialDomainName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CredentialDomainName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CredentialUserName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CredentialUserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CredentialPassword(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CredentialPassword());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics> : produce_base<D, winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics>
    {
        int32_t __stdcall PickWithOptionsAsync(void* options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>>(this->shim().PickAsync(*reinterpret_cast<winrt::Windows::Security::Credentials::UI::CredentialPickerOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickWithMessageAsync(void* targetName, void* message, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>>(this->shim().PickAsync(*reinterpret_cast<hstring const*>(&targetName), *reinterpret_cast<hstring const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PickWithCaptionAsync(void* targetName, void* message, void* caption, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::CredentialPickerResults>>(this->shim().PickAsync(*reinterpret_cast<hstring const*>(&targetName), *reinterpret_cast<hstring const*>(&message), *reinterpret_cast<hstring const*>(&caption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Security::Credentials::UI::IUserConsentVerifierStatics> : produce_base<D, winrt::Windows::Security::Credentials::UI::IUserConsentVerifierStatics>
    {
        int32_t __stdcall CheckAvailabilityAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::UserConsentVerifierAvailability>>(this->shim().CheckAvailabilityAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RequestVerificationAsync(void* message, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::UserConsentVerificationResult>>(this->shim().RequestVerificationAsync(*reinterpret_cast<hstring const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Security::Credentials::UI
{
    inline auto CredentialPicker::PickAsync(winrt::Windows::Security::Credentials::UI::CredentialPickerOptions const& options)
    {
        return impl::call_factory<CredentialPicker, ICredentialPickerStatics>([&](ICredentialPickerStatics const& f) { return f.PickAsync(options); });
    }
    inline auto CredentialPicker::PickAsync(param::hstring const& targetName, param::hstring const& message)
    {
        return impl::call_factory<CredentialPicker, ICredentialPickerStatics>([&](ICredentialPickerStatics const& f) { return f.PickAsync(targetName, message); });
    }
    inline auto CredentialPicker::PickAsync(param::hstring const& targetName, param::hstring const& message, param::hstring const& caption)
    {
        return impl::call_factory<CredentialPicker, ICredentialPickerStatics>([&](ICredentialPickerStatics const& f) { return f.PickAsync(targetName, message, caption); });
    }
    inline CredentialPickerOptions::CredentialPickerOptions() :
        CredentialPickerOptions(impl::call_factory_cast<CredentialPickerOptions(*)(winrt::Windows::Foundation::IActivationFactory const&), CredentialPickerOptions>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CredentialPickerOptions>(); }))
    {
    }
    inline auto UserConsentVerifier::CheckAvailabilityAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Credentials::UI::UserConsentVerifierAvailability>(*)(IUserConsentVerifierStatics const&), UserConsentVerifier, IUserConsentVerifierStatics>([](IUserConsentVerifierStatics const& f) { return f.CheckAvailabilityAsync(); });
    }
    inline auto UserConsentVerifier::RequestVerificationAsync(param::hstring const& message)
    {
        return impl::call_factory<UserConsentVerifier, IUserConsentVerifierStatics>([&](IUserConsentVerifierStatics const& f) { return f.RequestVerificationAsync(message); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::UI::ICredentialPickerResults> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::UI::IUserConsentVerifierStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::UI::CredentialPicker> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::UI::CredentialPickerOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::UI::CredentialPickerResults> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Security::Credentials::UI::UserConsentVerifier> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
