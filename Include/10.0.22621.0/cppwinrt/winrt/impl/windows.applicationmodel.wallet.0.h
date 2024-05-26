// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Wallet_0_H
#define WINRT_Windows_ApplicationModel_Wallet_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation
{
    struct BasicGeoposition;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename K, typename V> struct __declspec(empty_bases) IMap;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IRandomAccessStreamReference;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct Color;
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet
{
    enum class WalletActionKind : int32_t
    {
        OpenItem = 0,
        Transaction = 1,
        MoreTransactions = 2,
        Message = 3,
        Verb = 4,
    };
    enum class WalletBarcodeSymbology : int32_t
    {
        Invalid = 0,
        Upca = 1,
        Upce = 2,
        Ean13 = 3,
        Ean8 = 4,
        Itf = 5,
        Code39 = 6,
        Code128 = 7,
        Qr = 8,
        Pdf417 = 9,
        Aztec = 10,
        Custom = 100000,
    };
    enum class WalletDetailViewPosition : int32_t
    {
        Hidden = 0,
        HeaderField1 = 1,
        HeaderField2 = 2,
        PrimaryField1 = 3,
        PrimaryField2 = 4,
        SecondaryField1 = 5,
        SecondaryField2 = 6,
        SecondaryField3 = 7,
        SecondaryField4 = 8,
        SecondaryField5 = 9,
        CenterField1 = 10,
        FooterField1 = 11,
        FooterField2 = 12,
        FooterField3 = 13,
        FooterField4 = 14,
    };
    enum class WalletItemKind : int32_t
    {
        Invalid = 0,
        Deal = 1,
        General = 2,
        PaymentInstrument = 3,
        Ticket = 4,
        BoardingPass = 5,
        MembershipCard = 6,
    };
    enum class WalletSummaryViewPosition : int32_t
    {
        Hidden = 0,
        Field1 = 1,
        Field2 = 2,
    };
    struct IWalletBarcode;
    struct IWalletBarcodeFactory;
    struct IWalletItem;
    struct IWalletItemCustomProperty;
    struct IWalletItemCustomPropertyFactory;
    struct IWalletItemFactory;
    struct IWalletItemStore;
    struct IWalletItemStore2;
    struct IWalletManagerStatics;
    struct IWalletRelevantLocation;
    struct IWalletTransaction;
    struct IWalletVerb;
    struct IWalletVerbFactory;
    struct WalletBarcode;
    struct WalletItem;
    struct WalletItemCustomProperty;
    struct WalletItemStore;
    struct WalletManager;
    struct WalletRelevantLocation;
    struct WalletTransaction;
    struct WalletVerb;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletVerb>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletBarcode>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletItemStore>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletTransaction>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletVerb>{ using type = class_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletActionKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletItemKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletBarcode> = L"Windows.ApplicationModel.Wallet.WalletBarcode";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletItem> = L"Windows.ApplicationModel.Wallet.WalletItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty> = L"Windows.ApplicationModel.Wallet.WalletItemCustomProperty";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletItemStore> = L"Windows.ApplicationModel.Wallet.WalletItemStore";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletManager> = L"Windows.ApplicationModel.Wallet.WalletManager";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation> = L"Windows.ApplicationModel.Wallet.WalletRelevantLocation";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletTransaction> = L"Windows.ApplicationModel.Wallet.WalletTransaction";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletVerb> = L"Windows.ApplicationModel.Wallet.WalletVerb";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletActionKind> = L"Windows.ApplicationModel.Wallet.WalletActionKind";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology> = L"Windows.ApplicationModel.Wallet.WalletBarcodeSymbology";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition> = L"Windows.ApplicationModel.Wallet.WalletDetailViewPosition";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletItemKind> = L"Windows.ApplicationModel.Wallet.WalletItemKind";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition> = L"Windows.ApplicationModel.Wallet.WalletSummaryViewPosition";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode> = L"Windows.ApplicationModel.Wallet.IWalletBarcode";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory> = L"Windows.ApplicationModel.Wallet.IWalletBarcodeFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletItem> = L"Windows.ApplicationModel.Wallet.IWalletItem";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty> = L"Windows.ApplicationModel.Wallet.IWalletItemCustomProperty";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory> = L"Windows.ApplicationModel.Wallet.IWalletItemCustomPropertyFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory> = L"Windows.ApplicationModel.Wallet.IWalletItemFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore> = L"Windows.ApplicationModel.Wallet.IWalletItemStore";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2> = L"Windows.ApplicationModel.Wallet.IWalletItemStore2";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics> = L"Windows.ApplicationModel.Wallet.IWalletManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation> = L"Windows.ApplicationModel.Wallet.IWalletRelevantLocation";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction> = L"Windows.ApplicationModel.Wallet.IWalletTransaction";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletVerb> = L"Windows.ApplicationModel.Wallet.IWalletVerb";
    template <> inline constexpr auto& name_v<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory> = L"Windows.ApplicationModel.Wallet.IWalletVerbFactory";
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode>{ 0x4F857B29,0xDE80,0x4EA4,{ 0xA1,0xCD,0x81,0xCD,0x08,0x4D,0xAC,0x27 } }; // 4F857B29-DE80-4EA4-A1CD-81CD084DAC27
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>{ 0x30117161,0xED9C,0x469E,{ 0xBB,0xFD,0x30,0x6C,0x95,0xEA,0x71,0x08 } }; // 30117161-ED9C-469E-BBFD-306C95EA7108
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletItem>{ 0x20B54BE8,0x118D,0x4EC4,{ 0x99,0x6C,0xB9,0x63,0xE7,0xBD,0x3E,0x74 } }; // 20B54BE8-118D-4EC4-996C-B963E7BD3E74
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>{ 0xB94B40F3,0xFA00,0x40FD,{ 0x98,0xDC,0x9D,0xE4,0x66,0x97,0xF1,0xE7 } }; // B94B40F3-FA00-40FD-98DC-9DE46697F1E7
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>{ 0xD0046A44,0x61A1,0x41AA,{ 0xB2,0x59,0xA5,0x61,0x0A,0xB5,0xD5,0x75 } }; // D0046A44-61A1-41AA-B259-A5610AB5D575
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory>{ 0x53E27470,0x4F0B,0x4A3E,{ 0x99,0xE5,0x0B,0xBB,0x1E,0xAB,0x38,0xD4 } }; // 53E27470-4F0B-4A3E-99E5-0BBB1EAB38D4
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore>{ 0x7160484B,0x6D49,0x48F8,{ 0x91,0xA9,0x40,0xA1,0xD0,0xF1,0x3E,0xF4 } }; // 7160484B-6D49-48F8-91A9-40A1D0F13EF4
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2>{ 0x65E682F0,0x7009,0x4A15,{ 0xBD,0x54,0x4F,0xFF,0x37,0x9B,0xFF,0xE2 } }; // 65E682F0-7009-4A15-BD54-4FFF379BFFE2
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics>{ 0x5111D6B8,0xC9A4,0x4C64,{ 0xB4,0xDD,0xE1,0xE5,0x48,0x00,0x1C,0x0D } }; // 5111D6B8-C9A4-4C64-B4DD-E1E548001C0D
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation>{ 0x9FD8782A,0xE3F9,0x4DE1,{ 0xBA,0xB3,0xBB,0x19,0x2E,0x46,0xB3,0xF3 } }; // 9FD8782A-E3F9-4DE1-BAB3-BB192E46B3F3
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction>{ 0x40E1E940,0x2606,0x4519,{ 0x81,0xCB,0xBF,0xF1,0xC6,0x0D,0x1F,0x79 } }; // 40E1E940-2606-4519-81CB-BFF1C60D1F79
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletVerb>{ 0x17B826D6,0xE3C1,0x4C74,{ 0x8A,0x94,0x21,0x7A,0xAD,0xBC,0x48,0x84 } }; // 17B826D6-E3C1-4C74-8A94-217AADBC4884
    template <> inline constexpr guid guid_v<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory>{ 0x76012771,0xBE58,0x4D5E,{ 0x83,0xED,0x58,0xB1,0x66,0x9C,0x7A,0xD9 } }; // 76012771-BE58-4D5E-83ED-58B1669C7AD9
    template <> struct default_interface<winrt::Windows::ApplicationModel::Wallet::WalletBarcode>{ using type = winrt::Windows::ApplicationModel::Wallet::IWalletBarcode; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Wallet::WalletItem>{ using type = winrt::Windows::ApplicationModel::Wallet::IWalletItem; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty>{ using type = winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Wallet::WalletItemStore>{ using type = winrt::Windows::ApplicationModel::Wallet::IWalletItemStore; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation>{ using type = winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Wallet::WalletTransaction>{ using type = winrt::Windows::ApplicationModel::Wallet::IWalletTransaction; };
    template <> struct default_interface<winrt::Windows::ApplicationModel::Wallet::WalletVerb>{ using type = winrt::Windows::ApplicationModel::Wallet::IWalletVerb; };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Symbology(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Value(void**) noexcept = 0;
            virtual int32_t __stdcall GetImageAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWalletBarcode(int32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateCustomWalletBarcode(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsAcknowledged(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsAcknowledged(bool) noexcept = 0;
            virtual int32_t __stdcall get_IssuerDisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall put_IssuerDisplayName(void*) noexcept = 0;
            virtual int32_t __stdcall get_LastUpdated(void**) noexcept = 0;
            virtual int32_t __stdcall put_LastUpdated(void*) noexcept = 0;
            virtual int32_t __stdcall get_Kind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Barcode(void**) noexcept = 0;
            virtual int32_t __stdcall put_Barcode(void*) noexcept = 0;
            virtual int32_t __stdcall get_ExpirationDate(void**) noexcept = 0;
            virtual int32_t __stdcall put_ExpirationDate(void*) noexcept = 0;
            virtual int32_t __stdcall get_Logo159x159(void**) noexcept = 0;
            virtual int32_t __stdcall put_Logo159x159(void*) noexcept = 0;
            virtual int32_t __stdcall get_Logo336x336(void**) noexcept = 0;
            virtual int32_t __stdcall put_Logo336x336(void*) noexcept = 0;
            virtual int32_t __stdcall get_Logo99x99(void**) noexcept = 0;
            virtual int32_t __stdcall put_Logo99x99(void*) noexcept = 0;
            virtual int32_t __stdcall get_DisplayMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayMessage(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsDisplayMessageLaunchable(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsDisplayMessageLaunchable(bool) noexcept = 0;
            virtual int32_t __stdcall get_LogoText(void**) noexcept = 0;
            virtual int32_t __stdcall put_LogoText(void*) noexcept = 0;
            virtual int32_t __stdcall get_HeaderColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall put_HeaderColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_BodyColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall put_BodyColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_HeaderFontColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall put_HeaderFontColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_BodyFontColor(struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall put_BodyFontColor(struct struct_Windows_UI_Color) noexcept = 0;
            virtual int32_t __stdcall get_HeaderBackgroundImage(void**) noexcept = 0;
            virtual int32_t __stdcall put_HeaderBackgroundImage(void*) noexcept = 0;
            virtual int32_t __stdcall get_BodyBackgroundImage(void**) noexcept = 0;
            virtual int32_t __stdcall put_BodyBackgroundImage(void*) noexcept = 0;
            virtual int32_t __stdcall get_LogoImage(void**) noexcept = 0;
            virtual int32_t __stdcall put_LogoImage(void*) noexcept = 0;
            virtual int32_t __stdcall get_PromotionalImage(void**) noexcept = 0;
            virtual int32_t __stdcall put_PromotionalImage(void*) noexcept = 0;
            virtual int32_t __stdcall get_RelevantDate(void**) noexcept = 0;
            virtual int32_t __stdcall put_RelevantDate(void*) noexcept = 0;
            virtual int32_t __stdcall get_RelevantDateDisplayMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_RelevantDateDisplayMessage(void*) noexcept = 0;
            virtual int32_t __stdcall get_TransactionHistory(void**) noexcept = 0;
            virtual int32_t __stdcall get_RelevantLocations(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsMoreTransactionHistoryLaunchable(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsMoreTransactionHistoryLaunchable(bool) noexcept = 0;
            virtual int32_t __stdcall get_DisplayProperties(void**) noexcept = 0;
            virtual int32_t __stdcall get_Verbs(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall put_Name(void*) noexcept = 0;
            virtual int32_t __stdcall get_Value(void**) noexcept = 0;
            virtual int32_t __stdcall put_Value(void*) noexcept = 0;
            virtual int32_t __stdcall get_AutoDetectLinks(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AutoDetectLinks(bool) noexcept = 0;
            virtual int32_t __stdcall get_DetailViewPosition(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_DetailViewPosition(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_SummaryViewPosition(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_SummaryViewPosition(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWalletItemCustomProperty(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWalletItem(int32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall AddAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ClearAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetWalletItemAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetItemsAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetItemsWithKindAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ImportItemAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall DeleteAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ShowAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ShowItemAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_ItemsChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ItemsChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestStoreAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition*) noexcept = 0;
            virtual int32_t __stdcall put_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition) noexcept = 0;
            virtual int32_t __stdcall get_DisplayMessage(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayMessage(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall put_Description(void*) noexcept = 0;
            virtual int32_t __stdcall get_DisplayAmount(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayAmount(void*) noexcept = 0;
            virtual int32_t __stdcall get_IgnoreTimeOfDay(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IgnoreTimeOfDay(bool) noexcept = 0;
            virtual int32_t __stdcall get_DisplayLocation(void**) noexcept = 0;
            virtual int32_t __stdcall put_DisplayLocation(void*) noexcept = 0;
            virtual int32_t __stdcall get_TransactionDate(void**) noexcept = 0;
            virtual int32_t __stdcall put_TransactionDate(void*) noexcept = 0;
            virtual int32_t __stdcall get_IsLaunchable(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsLaunchable(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletVerb>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall put_Name(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWalletVerb(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletBarcode
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology) Symbology() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Value() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>) GetImageAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletBarcode>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletBarcode<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcode) CreateWalletBarcode(winrt::Windows::ApplicationModel::Wallet::WalletBarcodeSymbology const& symbology, param::hstring const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcode) CreateCustomWalletBarcode(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& streamToBarcodeImage) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletBarcodeFactory>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletBarcodeFactory<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        WINRT_IMPL_AUTO(void) DisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAcknowledged() const;
        WINRT_IMPL_AUTO(void) IsAcknowledged(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) IssuerDisplayName() const;
        WINRT_IMPL_AUTO(void) IssuerDisplayName(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) LastUpdated() const;
        WINRT_IMPL_AUTO(void) LastUpdated(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletItemKind) Kind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletBarcode) Barcode() const;
        WINRT_IMPL_AUTO(void) Barcode(winrt::Windows::ApplicationModel::Wallet::WalletBarcode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) ExpirationDate() const;
        WINRT_IMPL_AUTO(void) ExpirationDate(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) Logo159x159() const;
        WINRT_IMPL_AUTO(void) Logo159x159(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) Logo336x336() const;
        WINRT_IMPL_AUTO(void) Logo336x336(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) Logo99x99() const;
        WINRT_IMPL_AUTO(void) Logo99x99(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayMessage() const;
        WINRT_IMPL_AUTO(void) DisplayMessage(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDisplayMessageLaunchable() const;
        WINRT_IMPL_AUTO(void) IsDisplayMessageLaunchable(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LogoText() const;
        WINRT_IMPL_AUTO(void) LogoText(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) HeaderColor() const;
        WINRT_IMPL_AUTO(void) HeaderColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) BodyColor() const;
        WINRT_IMPL_AUTO(void) BodyColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) HeaderFontColor() const;
        WINRT_IMPL_AUTO(void) HeaderFontColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Color) BodyFontColor() const;
        WINRT_IMPL_AUTO(void) BodyFontColor(winrt::Windows::UI::Color const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) HeaderBackgroundImage() const;
        WINRT_IMPL_AUTO(void) HeaderBackgroundImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) BodyBackgroundImage() const;
        WINRT_IMPL_AUTO(void) BodyBackgroundImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) LogoImage() const;
        WINRT_IMPL_AUTO(void) LogoImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) PromotionalImage() const;
        WINRT_IMPL_AUTO(void) PromotionalImage(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) RelevantDate() const;
        WINRT_IMPL_AUTO(void) RelevantDate(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) RelevantDateDisplayMessage() const;
        WINRT_IMPL_AUTO(void) RelevantDateDisplayMessage(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletTransaction>) TransactionHistory() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletRelevantLocation>) RelevantLocations() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsMoreTransactionHistoryLaunchable() const;
        WINRT_IMPL_AUTO(void) IsMoreTransactionHistoryLaunchable(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty>) DisplayProperties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::ApplicationModel::Wallet::WalletVerb>) Verbs() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletItem>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItem<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        WINRT_IMPL_AUTO(void) Name(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Value() const;
        WINRT_IMPL_AUTO(void) Value(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AutoDetectLinks() const;
        WINRT_IMPL_AUTO(void) AutoDetectLinks(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition) DetailViewPosition() const;
        WINRT_IMPL_AUTO(void) DetailViewPosition(winrt::Windows::ApplicationModel::Wallet::WalletDetailViewPosition const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition) SummaryViewPosition() const;
        WINRT_IMPL_AUTO(void) SummaryViewPosition(winrt::Windows::ApplicationModel::Wallet::WalletSummaryViewPosition const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomProperty>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemCustomProperty<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletItemCustomPropertyFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletItemCustomProperty) CreateWalletItemCustomProperty(param::hstring const& name, param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletItemCustomPropertyFactory>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemCustomPropertyFactory<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletItemFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletItem) CreateWalletItem(winrt::Windows::ApplicationModel::Wallet::WalletItemKind const& kind, param::hstring const& displayName) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletItemFactory>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemFactory<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletItemStore
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AddAsync(param::hstring const& id, winrt::Windows::ApplicationModel::Wallet::WalletItem const& item) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ClearAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>) GetWalletItemAsync(param::hstring const& id) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>) GetItemsAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::ApplicationModel::Wallet::WalletItem>>) GetItemsAsync(winrt::Windows::ApplicationModel::Wallet::WalletItemKind const& kind) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItem>) ImportItemAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& stream) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DeleteAsync(param::hstring const& id) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ShowAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ShowAsync(param::hstring const& id) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) UpdateAsync(winrt::Windows::ApplicationModel::Wallet::WalletItem const& item) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemStore<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletItemStore2
    {
        WINRT_IMPL_AUTO(winrt::event_token) ItemsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Wallet::WalletItemStore, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ItemsChanged_revoker = impl::event_revoker<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2, &impl::abi_t<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2>::remove_ItemsChanged>;
        [[nodiscard]] ItemsChanged_revoker ItemsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Wallet::WalletItemStore, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ItemsChanged(winrt::event_token const& cookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletItemStore2>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletItemStore2<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::ApplicationModel::Wallet::WalletItemStore>) RequestStoreAsync() const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletManagerStatics>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Geolocation::BasicGeoposition) Position() const;
        WINRT_IMPL_AUTO(void) Position(winrt::Windows::Devices::Geolocation::BasicGeoposition const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayMessage() const;
        WINRT_IMPL_AUTO(void) DisplayMessage(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletRelevantLocation>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletRelevantLocation<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletTransaction
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        WINRT_IMPL_AUTO(void) Description(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayAmount() const;
        WINRT_IMPL_AUTO(void) DisplayAmount(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IgnoreTimeOfDay() const;
        WINRT_IMPL_AUTO(void) IgnoreTimeOfDay(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayLocation() const;
        WINRT_IMPL_AUTO(void) DisplayLocation(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) TransactionDate() const;
        WINRT_IMPL_AUTO(void) TransactionDate(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLaunchable() const;
        WINRT_IMPL_AUTO(void) IsLaunchable(bool value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletTransaction>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletTransaction<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletVerb
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        WINRT_IMPL_AUTO(void) Name(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletVerb>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletVerb<D>;
    };
    template <typename D>
    struct consume_Windows_ApplicationModel_Wallet_IWalletVerbFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Wallet::WalletVerb) CreateWalletVerb(param::hstring const& name) const;
    };
    template <> struct consume<winrt::Windows::ApplicationModel::Wallet::IWalletVerbFactory>
    {
        template <typename D> using type = consume_Windows_ApplicationModel_Wallet_IWalletVerbFactory<D>;
    };
}
#endif
