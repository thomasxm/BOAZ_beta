// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_NumberFormatting_0_H
#define WINRT_Windows_Globalization_NumberFormatting_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) IReference;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Globalization::NumberFormatting
{
    enum class CurrencyFormatterMode : int32_t
    {
        UseSymbol = 0,
        UseCurrencyCode = 1,
    };
    enum class RoundingAlgorithm : int32_t
    {
        None = 0,
        RoundDown = 1,
        RoundUp = 2,
        RoundTowardsZero = 3,
        RoundAwayFromZero = 4,
        RoundHalfDown = 5,
        RoundHalfUp = 6,
        RoundHalfTowardsZero = 7,
        RoundHalfAwayFromZero = 8,
        RoundHalfToEven = 9,
        RoundHalfToOdd = 10,
    };
    struct ICurrencyFormatter;
    struct ICurrencyFormatter2;
    struct ICurrencyFormatterFactory;
    struct IDecimalFormatterFactory;
    struct IIncrementNumberRounder;
    struct INumberFormatter;
    struct INumberFormatter2;
    struct INumberFormatterOptions;
    struct INumberParser;
    struct INumberRounder;
    struct INumberRounderOption;
    struct INumeralSystemTranslator;
    struct INumeralSystemTranslatorFactory;
    struct IPercentFormatterFactory;
    struct IPermilleFormatterFactory;
    struct ISignedZeroOption;
    struct ISignificantDigitsNumberRounder;
    struct ISignificantDigitsOption;
    struct CurrencyFormatter;
    struct DecimalFormatter;
    struct IncrementNumberRounder;
    struct NumeralSystemTranslator;
    struct PercentFormatter;
    struct PermilleFormatter;
    struct SignificantDigitsNumberRounder;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumberFormatter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumberFormatter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumberParser>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumberRounder>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumberRounderOption>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::DecimalFormatter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::IncrementNumberRounder>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::PercentFormatter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::PermilleFormatter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::SignificantDigitsNumberRounder>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter> = L"Windows.Globalization.NumberFormatting.CurrencyFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::DecimalFormatter> = L"Windows.Globalization.NumberFormatting.DecimalFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::IncrementNumberRounder> = L"Windows.Globalization.NumberFormatting.IncrementNumberRounder";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator> = L"Windows.Globalization.NumberFormatting.NumeralSystemTranslator";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::PercentFormatter> = L"Windows.Globalization.NumberFormatting.PercentFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::PermilleFormatter> = L"Windows.Globalization.NumberFormatting.PermilleFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::SignificantDigitsNumberRounder> = L"Windows.Globalization.NumberFormatting.SignificantDigitsNumberRounder";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode> = L"Windows.Globalization.NumberFormatting.CurrencyFormatterMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm> = L"Windows.Globalization.NumberFormatting.RoundingAlgorithm";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter> = L"Windows.Globalization.NumberFormatting.ICurrencyFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2> = L"Windows.Globalization.NumberFormatting.ICurrencyFormatter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory> = L"Windows.Globalization.NumberFormatting.ICurrencyFormatterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory> = L"Windows.Globalization.NumberFormatting.IDecimalFormatterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder> = L"Windows.Globalization.NumberFormatting.IIncrementNumberRounder";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumberFormatter> = L"Windows.Globalization.NumberFormatting.INumberFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumberFormatter2> = L"Windows.Globalization.NumberFormatting.INumberFormatter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions> = L"Windows.Globalization.NumberFormatting.INumberFormatterOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumberParser> = L"Windows.Globalization.NumberFormatting.INumberParser";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumberRounder> = L"Windows.Globalization.NumberFormatting.INumberRounder";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumberRounderOption> = L"Windows.Globalization.NumberFormatting.INumberRounderOption";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator> = L"Windows.Globalization.NumberFormatting.INumeralSystemTranslator";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory> = L"Windows.Globalization.NumberFormatting.INumeralSystemTranslatorFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory> = L"Windows.Globalization.NumberFormatting.IPercentFormatterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory> = L"Windows.Globalization.NumberFormatting.IPermilleFormatterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption> = L"Windows.Globalization.NumberFormatting.ISignedZeroOption";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder> = L"Windows.Globalization.NumberFormatting.ISignificantDigitsNumberRounder";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption> = L"Windows.Globalization.NumberFormatting.ISignificantDigitsOption";
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter>{ 0x11730CA5,0x4B00,0x41B2,{ 0xB3,0x32,0x73,0xB1,0x2A,0x49,0x7D,0x54 } }; // 11730CA5-4B00-41B2-B332-73B12A497D54
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2>{ 0x072C2F1D,0xE7BA,0x4197,{ 0x92,0x0E,0x24,0x7C,0x92,0xF7,0xDE,0xA6 } }; // 072C2F1D-E7BA-4197-920E-247C92F7DEA6
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory>{ 0x86C7537E,0xB938,0x4AA2,{ 0x84,0xB0,0x2C,0x33,0xDC,0x5B,0x14,0x50 } }; // 86C7537E-B938-4AA2-84B0-2C33DC5B1450
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory>{ 0x0D018C9A,0xE393,0x46B8,{ 0xB8,0x30,0x7A,0x69,0xC8,0xF8,0x9F,0xBB } }; // 0D018C9A-E393-46B8-B830-7A69C8F89FBB
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder>{ 0x70A64FF8,0x66AB,0x4155,{ 0x9D,0xA1,0x73,0x9E,0x46,0x76,0x45,0x43 } }; // 70A64FF8-66AB-4155-9DA1-739E46764543
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumberFormatter>{ 0xA5007C49,0x7676,0x4DB7,{ 0x86,0x31,0x1B,0x6F,0xF2,0x65,0xCA,0xA9 } }; // A5007C49-7676-4DB7-8631-1B6FF265CAA9
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumberFormatter2>{ 0xD4A8C1F0,0x80D0,0x4B0D,{ 0xA8,0x9E,0x88,0x2C,0x1E,0x8F,0x83,0x10 } }; // D4A8C1F0-80D0-4B0D-A89E-882C1E8F8310
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions>{ 0x80332D21,0xAEE1,0x4A39,{ 0xBA,0xA2,0x07,0xED,0x8C,0x96,0xDA,0xF6 } }; // 80332D21-AEE1-4A39-BAA2-07ED8C96DAF6
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumberParser>{ 0xE6659412,0x4A13,0x4A53,{ 0x83,0xA1,0x39,0x2F,0xBE,0x4C,0xFF,0x9F } }; // E6659412-4A13-4A53-83A1-392FBE4CFF9F
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumberRounder>{ 0x5473C375,0x38ED,0x4631,{ 0xB8,0x0C,0xEF,0x34,0xFC,0x48,0xB7,0xF5 } }; // 5473C375-38ED-4631-B80C-EF34FC48B7F5
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumberRounderOption>{ 0x3B088433,0x646F,0x4EFE,{ 0x8D,0x48,0x66,0xEB,0x2E,0x49,0xE7,0x36 } }; // 3B088433-646F-4EFE-8D48-66EB2E49E736
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator>{ 0x28F5BC2C,0x8C23,0x4234,{ 0xAD,0x2E,0xFA,0x5A,0x3A,0x42,0x6E,0x9B } }; // 28F5BC2C-8C23-4234-AD2E-FA5A3A426E9B
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory>{ 0x9630C8DA,0x36EF,0x4D88,{ 0xA8,0x5C,0x6F,0x0D,0x98,0xD6,0x20,0xA6 } }; // 9630C8DA-36EF-4D88-A85C-6F0D98D620A6
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory>{ 0xB7828AEF,0xFED4,0x4018,{ 0xA6,0xE2,0xE0,0x99,0x61,0xE0,0x37,0x65 } }; // B7828AEF-FED4-4018-A6E2-E09961E03765
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory>{ 0x2B37B4AC,0xE638,0x4ED5,{ 0xA9,0x98,0x62,0xF6,0xB0,0x6A,0x49,0xAE } }; // 2B37B4AC-E638-4ED5-A998-62F6B06A49AE
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>{ 0xFD1CDD31,0x0A3C,0x49C4,{ 0xA6,0x42,0x96,0xA1,0x56,0x4F,0x4F,0x30 } }; // FD1CDD31-0A3C-49C4-A642-96A1564F4F30
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder>{ 0xF5941BCA,0x6646,0x4913,{ 0x8C,0x76,0x1B,0x19,0x1F,0xF9,0x4D,0xFD } }; // F5941BCA-6646-4913-8C76-1B191FF94DFD
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption>{ 0x1D4DFCDD,0x2D43,0x4EE8,{ 0xBB,0xF1,0xC1,0xB2,0x6A,0x71,0x1A,0x58 } }; // 1D4DFCDD-2D43-4EE8-BBF1-C1B26A711A58
    template <> struct default_interface<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter>{ using type = winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter; };
    template <> struct default_interface<winrt::Windows::Globalization::NumberFormatting::DecimalFormatter>{ using type = winrt::Windows::Globalization::NumberFormatting::INumberFormatter; };
    template <> struct default_interface<winrt::Windows::Globalization::NumberFormatting::IncrementNumberRounder>{ using type = winrt::Windows::Globalization::NumberFormatting::INumberRounder; };
    template <> struct default_interface<winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator>{ using type = winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator; };
    template <> struct default_interface<winrt::Windows::Globalization::NumberFormatting::PercentFormatter>{ using type = winrt::Windows::Globalization::NumberFormatting::INumberFormatter; };
    template <> struct default_interface<winrt::Windows::Globalization::NumberFormatting::PermilleFormatter>{ using type = winrt::Windows::Globalization::NumberFormatting::INumberFormatter; };
    template <> struct default_interface<winrt::Windows::Globalization::NumberFormatting::SignificantDigitsNumberRounder>{ using type = winrt::Windows::Globalization::NumberFormatting::INumberRounder; };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Currency(void**) noexcept = 0;
            virtual int32_t __stdcall put_Currency(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Mode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Mode(int32_t) noexcept = 0;
            virtual int32_t __stdcall ApplyRoundingForCurrency(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateCurrencyFormatterCode(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateCurrencyFormatterCodeContext(void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateDecimalFormatter(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RoundingAlgorithm(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_RoundingAlgorithm(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_Increment(double*) noexcept = 0;
            virtual int32_t __stdcall put_Increment(double) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumberFormatter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FormatInt(int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall FormatUInt(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall FormatDouble(double, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumberFormatter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FormatInt(int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall FormatUInt(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall FormatDouble(double, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Languages(void**) noexcept = 0;
            virtual int32_t __stdcall get_GeographicRegion(void**) noexcept = 0;
            virtual int32_t __stdcall get_IntegerDigits(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_IntegerDigits(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_FractionDigits(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_FractionDigits(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsGrouped(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsGrouped(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsDecimalPointAlwaysDisplayed(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsDecimalPointAlwaysDisplayed(bool) noexcept = 0;
            virtual int32_t __stdcall get_NumeralSystem(void**) noexcept = 0;
            virtual int32_t __stdcall put_NumeralSystem(void*) noexcept = 0;
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall get_ResolvedGeographicRegion(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumberParser>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ParseInt(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ParseUInt(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ParseDouble(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumberRounder>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RoundInt32(int32_t, int32_t*) noexcept = 0;
            virtual int32_t __stdcall RoundUInt32(uint32_t, uint32_t*) noexcept = 0;
            virtual int32_t __stdcall RoundInt64(int64_t, int64_t*) noexcept = 0;
            virtual int32_t __stdcall RoundUInt64(uint64_t, uint64_t*) noexcept = 0;
            virtual int32_t __stdcall RoundSingle(float, float*) noexcept = 0;
            virtual int32_t __stdcall RoundDouble(double, double*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumberRounderOption>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_NumberRounder(void**) noexcept = 0;
            virtual int32_t __stdcall put_NumberRounder(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Languages(void**) noexcept = 0;
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall get_NumeralSystem(void**) noexcept = 0;
            virtual int32_t __stdcall put_NumeralSystem(void*) noexcept = 0;
            virtual int32_t __stdcall TranslateNumerals(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreatePercentFormatter(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreatePermilleFormatter(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsZeroSigned(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsZeroSigned(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RoundingAlgorithm(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_RoundingAlgorithm(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_SignificantDigits(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_SignificantDigits(uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SignificantDigits(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_SignificantDigits(int32_t) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Currency() const;
        WINRT_IMPL_AUTO(void) Currency(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode) Mode() const;
        WINRT_IMPL_AUTO(void) Mode(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode const& value) const;
        WINRT_IMPL_AUTO(void) ApplyRoundingForCurrency(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const& roundingAlgorithm) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter2<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_ICurrencyFormatterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter) CreateCurrencyFormatterCode(param::hstring const& currencyCode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter) CreateCurrencyFormatterCodeContext(param::hstring const& currencyCode, param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_ICurrencyFormatterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_IDecimalFormatterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::DecimalFormatter) CreateDecimalFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_IDecimalFormatterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_IIncrementNumberRounder
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm) RoundingAlgorithm() const;
        WINRT_IMPL_AUTO(void) RoundingAlgorithm(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) Increment() const;
        WINRT_IMPL_AUTO(void) Increment(double value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_IIncrementNumberRounder<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumberFormatter
    {
        WINRT_IMPL_AUTO(hstring) Format(int64_t value) const;
        WINRT_IMPL_AUTO(hstring) Format(uint64_t value) const;
        WINRT_IMPL_AUTO(hstring) Format(double value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumberFormatter>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumberFormatter<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumberFormatter2
    {
        WINRT_IMPL_AUTO(hstring) FormatInt(int64_t value) const;
        WINRT_IMPL_AUTO(hstring) FormatUInt(uint64_t value) const;
        WINRT_IMPL_AUTO(hstring) FormatDouble(double value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumberFormatter2>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumberFormatter2<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Languages() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) GeographicRegion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) IntegerDigits() const;
        WINRT_IMPL_AUTO(void) IntegerDigits(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) FractionDigits() const;
        WINRT_IMPL_AUTO(void) FractionDigits(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsGrouped() const;
        WINRT_IMPL_AUTO(void) IsGrouped(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDecimalPointAlwaysDisplayed() const;
        WINRT_IMPL_AUTO(void) IsDecimalPointAlwaysDisplayed(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NumeralSystem() const;
        WINRT_IMPL_AUTO(void) NumeralSystem(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedGeographicRegion() const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumberParser
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int64_t>) ParseInt(param::hstring const& text) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint64_t>) ParseUInt(param::hstring const& text) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) ParseDouble(param::hstring const& text) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumberParser>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumberParser<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumberRounder
    {
        WINRT_IMPL_AUTO(int32_t) RoundInt32(int32_t value) const;
        WINRT_IMPL_AUTO(uint32_t) RoundUInt32(uint32_t value) const;
        WINRT_IMPL_AUTO(int64_t) RoundInt64(int64_t value) const;
        WINRT_IMPL_AUTO(uint64_t) RoundUInt64(uint64_t value) const;
        WINRT_IMPL_AUTO(float) RoundSingle(float value) const;
        WINRT_IMPL_AUTO(double) RoundDouble(double value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumberRounder>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumberRounder<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumberRounderOption
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::INumberRounder) NumberRounder() const;
        WINRT_IMPL_AUTO(void) NumberRounder(winrt::Windows::Globalization::NumberFormatting::INumberRounder const& value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumberRounderOption>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumberRounderOption<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslator
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Languages() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NumeralSystem() const;
        WINRT_IMPL_AUTO(void) NumeralSystem(param::hstring const& value) const;
        WINRT_IMPL_AUTO(hstring) TranslateNumerals(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslator<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslatorFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator) Create(param::iterable<hstring> const& languages) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslatorFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_IPercentFormatterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::PercentFormatter) CreatePercentFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_IPercentFormatterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_IPermilleFormatterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::PermilleFormatter) CreatePermilleFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_IPermilleFormatterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_ISignedZeroOption
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsZeroSigned() const;
        WINRT_IMPL_AUTO(void) IsZeroSigned(bool value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_ISignedZeroOption<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_ISignificantDigitsNumberRounder
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm) RoundingAlgorithm() const;
        WINRT_IMPL_AUTO(void) RoundingAlgorithm(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SignificantDigits() const;
        WINRT_IMPL_AUTO(void) SignificantDigits(uint32_t value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_ISignificantDigitsNumberRounder<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_NumberFormatting_ISignificantDigitsOption
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) SignificantDigits() const;
        WINRT_IMPL_AUTO(void) SignificantDigits(int32_t value) const;
    };
    template <> struct consume<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption>
    {
        template <typename D> using type = consume_Windows_Globalization_NumberFormatting_ISignificantDigitsOption<D>;
    };
}
#endif
