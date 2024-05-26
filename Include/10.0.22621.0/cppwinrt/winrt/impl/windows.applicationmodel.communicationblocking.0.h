// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_CommunicationBlocking_0_H
#define WINRT_Windows_ApplicationModel_CommunicationBlocking_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::CommunicationBlocking
{
    struct ICommunicationBlockingAccessManagerStatics;
    struct ICommunicationBlockingAppManagerStatics;
    struct ICommunicationBlockingAppManagerStatics2;
    struct CommunicationBlockingAccessManager;
    struct CommunicationBlockingAppManager;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAccessManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAppManager>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAccessManager> = L"Windows.ApplicationModel.CommunicationBlocking.CommunicationBlockingAccessManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAppManager> = L"Windows.ApplicationModel.CommunicationBlocking.CommunicationBlockingAppManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics> = L"Windows.ApplicationModel.CommunicationBlocking.ICommunicationBlockingAccessManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics> = L"Windows.ApplicationModel.CommunicationBlocking.ICommunicationBlockingAppManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2> = L"Windows.ApplicationModel.CommunicationBlocking.ICommunicationBlockingAppManagerStatics2";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>{ 0x1C969998,0x9D2A,0x5DB7,{ 0xED,0xD5,0x0C,0xE4,0x07,0xFC,0x25,0x95 } }; // 1C969998-9D2A-5DB7-EDD5-0CE407FC2595
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>{ 0x77DB58EC,0x14A6,0x4BAA,{ 0x94,0x2A,0x6A,0x67,0x3D,0x99,0x9B,0xF2 } }; // 77DB58EC-14A6-4BAA-942A-6A673D999BF2
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2>{ 0x14A68EDD,0xED88,0x457A,{ 0xA3,0x64,0xA3,0x63,0x4D,0x6F,0x16,0x6D } }; // 14A68EDD-ED88-457A-A364-A3634D6F166D
    template <> struct abi<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsBlockingActive(bool*) noexcept = 0;
            virtual int32_t __stdcall IsBlockedNumberAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ShowBlockNumbersUI(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall ShowUnblockNumbersUI(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall ShowBlockedCallsUI() noexcept = 0;
            virtual int32_t __stdcall ShowBlockedMessagesUI() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsCurrentAppActiveBlockingApp(bool*) noexcept = 0;
            virtual int32_t __stdcall ShowCommunicationBlockingSettingsUI() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestSetAsActiveBlockingAppAsync(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBlockingActive() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) IsBlockedNumberAsync(param::hstring const& number) const;
        WINRT_IMPL_AUTO(bool) ShowBlockNumbersUI(param::iterable<hstring> const& phoneNumbers) const;
        WINRT_IMPL_AUTO(bool) ShowUnblockNumbersUI(param::iterable<hstring> const& phoneNumbers) const;
        WINRT_IMPL_AUTO(void) ShowBlockedCallsUI() const;
        WINRT_IMPL_AUTO(void) ShowBlockedMessagesUI() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCurrentAppActiveBlockingApp() const;
        WINRT_IMPL_AUTO(void) ShowCommunicationBlockingSettingsUI() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestSetAsActiveBlockingAppAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics2<D>;
    };
}
#endif
