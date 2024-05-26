// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Contacts_Provider_0_H
#define WINRT_Windows_ApplicationModel_Contacts_Provider_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts
{
    struct Contact;
    enum class ContactFieldType : int32_t;
    enum class ContactSelectionMode : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::Provider
{
    enum class AddContactResult : int32_t
    {
        Added = 0,
        AlreadyAdded = 1,
        Unavailable = 2,
    };
    struct IContactPickerUI;
    struct IContactPickerUI2;
    struct IContactRemovedEventArgs;
    struct ContactPickerUI;
    struct ContactRemovedEventArgs;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI> = L"Windows.ApplicationModel.Contacts.Provider.ContactPickerUI";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> = L"Windows.ApplicationModel.Contacts.Provider.ContactRemovedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult> = L"Windows.ApplicationModel.Contacts.Provider.AddContactResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI> = L"Windows.ApplicationModel.Contacts.Provider.IContactPickerUI";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2> = L"Windows.ApplicationModel.Contacts.Provider.IContactPickerUI2";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs> = L"Windows.ApplicationModel.Contacts.Provider.IContactRemovedEventArgs";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>{ 0xE2CC1366,0xCF66,0x43C4,{ 0xA9,0x6A,0xA5,0xA1,0x12,0xDB,0x47,0x46 } }; // E2CC1366-CF66-43C4-A96A-A5A112DB4746
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>{ 0x6E449E28,0x7B25,0x4999,{ 0x9B,0x0B,0x87,0x54,0x00,0xA1,0xE8,0xC8 } }; // 6E449E28-7B25-4999-9B0B-875400A1E8C8
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>{ 0x6F354338,0x3302,0x4D13,{ 0xAD,0x8D,0xAD,0xCC,0x0F,0xF9,0xE4,0x7C } }; // 6F354338-3302-4D13-AD8D-ADCC0FF9E47C
    template <> struct default_interface<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI>{ using type = winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs>{ using type = winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs; };
    template <> struct abi<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddContact(void*, void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall RemoveContact(void*) noexcept = 0;
            virtual int32_t __stdcall ContainsContact(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall get_DesiredFields(void**) noexcept = 0;
            virtual int32_t __stdcall get_SelectionMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_ContactRemoved(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ContactRemoved(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddContact(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DesiredFieldsWithContactFieldType(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult) AddContact(param::hstring const& id, winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const;
        WINRT_IMPL_AUTO(void) RemoveContact(param::hstring const& id) const;
        WINRT_IMPL_AUTO(bool) ContainsContact(param::hstring const& id) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) DesiredFields() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::ContactSelectionMode) SelectionMode() const;
        WINRT_IMPL_AUTO(winrt::event_token) ContactRemoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const;
        using ContactRemoved_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI, &impl::abi_t<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>::remove_ContactRemoved>;
        [[nodiscard]] ContactRemoved_revoker ContactRemoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Contacts::Provider::ContactPickerUI, winrt::Windows::ApplicationModel::Contacts::Provider::ContactRemovedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ContactRemoved(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Contacts::Provider::AddContactResult) AddContact(winrt::Windows::ApplicationModel::Contacts::Contact const& contact) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::ApplicationModel::Contacts::ContactFieldType>) DesiredFieldsWithContactFieldType() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Contacts::Provider::IContactPickerUI2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Contacts_Provider_IContactPickerUI2<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Contacts_Provider_IContactRemovedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Contacts::Provider::IContactRemovedEventArgs>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Contacts_Provider_IContactRemovedEventArgs<D>;
    };
}
#endif
