// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Contacts_Provider_H
#define WINRT_Windows_ApplicationModel_Contacts_Provider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Contacts.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.Provider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::AddContact(param::hstring const& id, winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->AddContact(*(void**)(&id), *(void**)(&contact), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::RemoveContact(param::hstring const& id) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->RemoveContact(*(void**)(&id)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContainsContact(param::hstring const& id) const
    {
        bool isContained{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->ContainsContact(*(void**)(&id), &isContained));
        return isContained;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::DesiredFields() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->get_DesiredFields(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::SelectionMode() const
    {
        winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->get_SelectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->add_ContactRemoved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved_revoker consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ContactRemoved_revoker>(this, ContactRemoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>::ContactRemoved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI)->remove_ContactRemoved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2<D>::AddContact(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const
    {
        winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2)->AddContact(*(void**)(&contact), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>) consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2<D>::DesiredFieldsWithContactFieldType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2)->get_DesiredFieldsWithContactFieldType(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Contacts_Provider_IContactRemovedEventArgs<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>
    {
        int32_t __stdcall AddContact(void* id, void* contact, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult>(this->shim().AddContact(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveContact(void* id) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveContact(*reinterpret_cast<hstring const*>(&id));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ContainsContact(void* id, bool* isContained) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *isContained = detach_from<bool>(this->shim().ContainsContact(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredFields(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().DesiredFields());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode>(this->shim().SelectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ContactRemoved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ContactRemoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ContactRemoved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ContactRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>
    {
        int32_t __stdcall AddContact(void* contact, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult>(this->shim().AddContact(*reinterpret_cast<winrt::Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredFieldsWithContactFieldType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>>(this->shim().DesiredFieldsWithContactFieldType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::Provider
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
