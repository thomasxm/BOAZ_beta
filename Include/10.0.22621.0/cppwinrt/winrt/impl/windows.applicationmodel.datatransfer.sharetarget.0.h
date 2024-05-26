// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_0_H
#define WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_0_H
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts
{
    struct Contact;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer
{
    struct DataPackageView;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct RandomAccessStreamReference;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget
{
    struct IQuickLink;
    struct IShareOperation;
    struct IShareOperation2;
    struct IShareOperation3;
    struct QuickLink;
    struct ShareOperation;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation>{ using type = class_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink> = L"Windows.ApplicationModel.DataTransfer.ShareTarget.QuickLink";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation> = L"Windows.ApplicationModel.DataTransfer.ShareTarget.ShareOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink> = L"Windows.ApplicationModel.DataTransfer.ShareTarget.IQuickLink";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation> = L"Windows.ApplicationModel.DataTransfer.ShareTarget.IShareOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2> = L"Windows.ApplicationModel.DataTransfer.ShareTarget.IShareOperation2";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3> = L"Windows.ApplicationModel.DataTransfer.ShareTarget.IShareOperation3";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>{ 0x603E4308,0xF0BE,0x4ADC,{ 0xAC,0xC9,0x8B,0x27,0xAB,0x9C,0xF5,0x56 } }; // 603E4308-F0BE-4ADC-ACC9-8B27AB9CF556
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>{ 0x2246BAB8,0xD0F8,0x41C1,{ 0xA8,0x2A,0x41,0x37,0xDB,0x65,0x04,0xFB } }; // 2246BAB8-D0F8-41C1-A82A-4137DB6504FB
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>{ 0x0FFB97C1,0x9778,0x4A09,{ 0x8E,0x5B,0xCB,0x5E,0x48,0x2D,0x05,0x55 } }; // 0FFB97C1-9778-4A09-8E5B-CB5E482D0555
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>{ 0x5EF6B382,0xB7A7,0x4571,{ 0xA2,0xA6,0x99,0x4A,0x03,0x49,0x88,0xB2 } }; // 5EF6B382-B7A7-4571-A2A6-994A034988B2
    template <> struct default_interface<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink>{ using type = winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::ShareOperation>{ using type = winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation; };
    template <> struct abi<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall put_Title(void*) noexcept = 0;
            virtual int32_t __stdcall get_Thumbnail(void**) noexcept = 0;
            virtual int32_t __stdcall put_Thumbnail(void*) noexcept = 0;
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall put_Id(void*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedDataFormats(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedFileTypes(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall get_QuickLinkId(void**) noexcept = 0;
            virtual int32_t __stdcall RemoveThisQuickLink() noexcept = 0;
            virtual int32_t __stdcall ReportStarted() noexcept = 0;
            virtual int32_t __stdcall ReportDataRetrieved() noexcept = 0;
            virtual int32_t __stdcall ReportSubmittedBackgroundTask() noexcept = 0;
            virtual int32_t __stdcall ReportCompletedWithQuickLink(void*) noexcept = 0;
            virtual int32_t __stdcall ReportCompleted() noexcept = 0;
            virtual int32_t __stdcall ReportError(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall DismissUI() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Contacts(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        WINRT_IMPL_AUTO(void) Title(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) Thumbnail() const;
        WINRT_IMPL_AUTO(void) Thumbnail(winrt::Windows::Storage::Streams::RandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        WINRT_IMPL_AUTO(void) Id(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) SupportedDataFormats() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) SupportedFileTypes() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IQuickLink<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::DataTransfer::DataPackageView) Data() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) QuickLinkId() const;
        WINRT_IMPL_AUTO(void) RemoveThisQuickLink() const;
        WINRT_IMPL_AUTO(void) ReportStarted() const;
        WINRT_IMPL_AUTO(void) ReportDataRetrieved() const;
        WINRT_IMPL_AUTO(void) ReportSubmittedBackgroundTask() const;
        WINRT_IMPL_AUTO(void) ReportCompleted(winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::QuickLink const& quicklink) const;
        WINRT_IMPL_AUTO(void) ReportCompleted() const;
        WINRT_IMPL_AUTO(void) ReportError(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation2
    {
        WINRT_IMPL_AUTO(void) DismissUI() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation2<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Contacts::Contact>) Contacts() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_DataTransfer_ShareTarget_IShareOperation3<D>;
    };
}
#endif
