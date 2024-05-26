// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Store_LicenseManagement_0_H
#define WINRT_Windows_ApplicationModel_Store_LicenseManagement_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct HResult;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::LicenseManagement
{
    enum class LicenseRefreshOption : int32_t
    {
        RunningLicenses = 0,
        AllLicenses = 1,
    };
    struct ILicenseManagerStatics;
    struct ILicenseManagerStatics2;
    struct ILicenseSatisfactionInfo;
    struct ILicenseSatisfactionResult;
    struct LicenseManager;
    struct LicenseSatisfactionInfo;
    struct LicenseSatisfactionResult;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseRefreshOption>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseManager> = L"Windows.ApplicationModel.Store.LicenseManagement.LicenseManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo> = L"Windows.ApplicationModel.Store.LicenseManagement.LicenseSatisfactionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult> = L"Windows.ApplicationModel.Store.LicenseManagement.LicenseSatisfactionResult";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseRefreshOption> = L"Windows.ApplicationModel.Store.LicenseManagement.LicenseRefreshOption";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics> = L"Windows.ApplicationModel.Store.LicenseManagement.ILicenseManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2> = L"Windows.ApplicationModel.Store.LicenseManagement.ILicenseManagerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo> = L"Windows.ApplicationModel.Store.LicenseManagement.ILicenseSatisfactionInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult> = L"Windows.ApplicationModel.Store.LicenseManagement.ILicenseSatisfactionResult";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics>{ 0xB5AC3AE0,0xDA47,0x4F20,{ 0x9A,0x23,0x09,0x18,0x2C,0x94,0x76,0xFF } }; // B5AC3AE0-DA47-4F20-9A23-09182C9476FF
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2>{ 0xAB2EC47B,0x1F79,0x4480,{ 0xB8,0x7E,0x2C,0x49,0x9E,0x60,0x1B,0xA3 } }; // AB2EC47B-1F79-4480-B87E-2C499E601BA3
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo>{ 0x3CCBB08F,0xDB31,0x48D5,{ 0x83,0x84,0xFA,0x17,0xC8,0x14,0x74,0xE2 } }; // 3CCBB08F-DB31-48D5-8384-FA17C81474E2
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult>{ 0x3C674F73,0x3C87,0x4EE1,{ 0x82,0x01,0xF4,0x28,0x35,0x9B,0xD3,0xAF } }; // 3C674F73-3C87-4EE1-8201-F428359BD3AF
    template <> struct default_interface<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo>{ using type = winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult>{ using type = winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult; };
    template <> struct abi<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddLicenseAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetSatisfactionInfosAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RefreshLicensesAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SatisfiedByDevice(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SatisfiedByOpenLicense(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SatisfiedByTrial(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SatisfiedByPass(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SatisfiedByInstallMedia(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SatisfiedBySignedInUser(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSatisfied(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LicenseSatisfactionInfos(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AddLicenseAsync(winrt::Windows::Storage::Streams::IBuffer const& license) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionResult>) GetSatisfactionInfosAsync(param::async_iterable<hstring> const& contentIds, param::async_iterable<hstring> const& keyIds) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseManagerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) RefreshLicensesAsync(winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseRefreshOption const& refreshOption) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseManagerStatics2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseManagerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SatisfiedByDevice() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SatisfiedByOpenLicense() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SatisfiedByTrial() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SatisfiedByPass() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SatisfiedByInstallMedia() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SatisfiedBySignedInUser() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSatisfied() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionInfo>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionInfo<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionResult
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::ApplicationModel::Store::LicenseManagement::LicenseSatisfactionInfo>) LicenseSatisfactionInfos() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Store::LicenseManagement::ILicenseSatisfactionResult>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Store_LicenseManagement_ILicenseSatisfactionResult<D>;
    };
}
#endif
