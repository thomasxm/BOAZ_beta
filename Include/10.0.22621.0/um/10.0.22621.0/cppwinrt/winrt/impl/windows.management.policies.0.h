// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Policies_0_H
#define WINRT_Windows_Management_Policies_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct User;
}
WINRT_EXPORT namespace winrt::Windows::Management::Policies
{
    enum class NamedPolicyKind : int32_t
    {
        Invalid = 0,
        Binary = 1,
        Boolean = 2,
        Int32 = 3,
        Int64 = 4,
        String = 5,
    };
    struct INamedPolicyData;
    struct INamedPolicyStatics;
    struct NamedPolicy;
    struct NamedPolicyData;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Management::Policies::INamedPolicyData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Policies::INamedPolicyStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Management::Policies::NamedPolicy>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Policies::NamedPolicyData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Management::Policies::NamedPolicyKind>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Policies::NamedPolicy> = L"Windows.Management.Policies.NamedPolicy";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Policies::NamedPolicyData> = L"Windows.Management.Policies.NamedPolicyData";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Policies::NamedPolicyKind> = L"Windows.Management.Policies.NamedPolicyKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Policies::INamedPolicyData> = L"Windows.Management.Policies.INamedPolicyData";
    template <> inline constexpr auto& name_v<winrt::Windows::Management::Policies::INamedPolicyStatics> = L"Windows.Management.Policies.INamedPolicyStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Policies::INamedPolicyData>{ 0x38DCB198,0x95AC,0x4077,{ 0xA6,0x43,0x80,0x78,0xCA,0xE2,0x64,0x00 } }; // 38DCB198-95AC-4077-A643-8078CAE26400
    template <> inline constexpr guid guid_v<winrt::Windows::Management::Policies::INamedPolicyStatics>{ 0x7F793BE7,0x76C4,0x4058,{ 0x8C,0xAD,0x67,0x66,0x2C,0xD0,0x5F,0x0D } }; // 7F793BE7-76C4-4058-8CAD-67662CD05F0D
    template <> struct default_interface<winrt::Windows::Management::Policies::NamedPolicyData>{ using type = winrt::Windows::Management::Policies::INamedPolicyData; };
    template <> struct abi<winrt::Windows::Management::Policies::INamedPolicyData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Area(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Kind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsManaged(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsUserPolicy(bool*) noexcept = 0;
            virtual int32_t __stdcall get_User(void**) noexcept = 0;
            virtual int32_t __stdcall GetBoolean(bool*) noexcept = 0;
            virtual int32_t __stdcall GetBinary(void**) noexcept = 0;
            virtual int32_t __stdcall GetInt32(int32_t*) noexcept = 0;
            virtual int32_t __stdcall GetInt64(int64_t*) noexcept = 0;
            virtual int32_t __stdcall GetString(void**) noexcept = 0;
            virtual int32_t __stdcall add_Changed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Changed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Management::Policies::INamedPolicyStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetPolicyFromPath(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetPolicyFromPathForUser(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Management_Policies_INamedPolicyData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Area() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Management::Policies::NamedPolicyKind) Kind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsManaged() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsUserPolicy() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::User) User() const;
        WINRT_IMPL_AUTO(bool) GetBoolean() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) GetBinary() const;
        WINRT_IMPL_AUTO(int32_t) GetInt32() const;
        WINRT_IMPL_AUTO(int64_t) GetInt64() const;
        WINRT_IMPL_AUTO(hstring) GetString() const;
        WINRT_IMPL_AUTO(winrt::event_token) Changed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Policies::NamedPolicyData, winrt::Windows::Foundation::IInspectable> const& changedHandler) const;
        using Changed_revoker = impl::event_revoker<winrt::Windows::Management::Policies::INamedPolicyData, &impl::abi_t<winrt::Windows::Management::Policies::INamedPolicyData>::remove_Changed>;
        [[nodiscard]] Changed_revoker Changed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Management::Policies::NamedPolicyData, winrt::Windows::Foundation::IInspectable> const& changedHandler) const;
        WINRT_IMPL_AUTO(void) Changed(winrt::event_token const& cookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::Management::Policies::INamedPolicyData>
    {
        template <typename D> using type = consume_Windows_Management_Policies_INamedPolicyData<D>;
    };
    template <typename D>
    struct consume_Windows_Management_Policies_INamedPolicyStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Management::Policies::NamedPolicyData) GetPolicyFromPath(param::hstring const& area, param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Management::Policies::NamedPolicyData) GetPolicyFromPathForUser(winrt::Windows::System::User const& user, param::hstring const& area, param::hstring const& name) const;
    };
    template <> struct consume<winrt::Windows::Management::Policies::INamedPolicyStatics>
    {
        template <typename D> using type = consume_Windows_Management_Policies_INamedPolicyStatics<D>;
    };
}
#endif
