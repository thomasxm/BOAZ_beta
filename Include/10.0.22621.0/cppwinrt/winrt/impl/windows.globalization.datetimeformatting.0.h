// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_DateTimeFormatting_0_H
#define WINRT_Windows_Globalization_DateTimeFormatting_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Globalization::DateTimeFormatting
{
    enum class DayFormat : int32_t
    {
        None = 0,
        Default = 1,
    };
    enum class DayOfWeekFormat : int32_t
    {
        None = 0,
        Default = 1,
        Abbreviated = 2,
        Full = 3,
    };
    enum class HourFormat : int32_t
    {
        None = 0,
        Default = 1,
    };
    enum class MinuteFormat : int32_t
    {
        None = 0,
        Default = 1,
    };
    enum class MonthFormat : int32_t
    {
        None = 0,
        Default = 1,
        Abbreviated = 2,
        Full = 3,
        Numeric = 4,
    };
    enum class SecondFormat : int32_t
    {
        None = 0,
        Default = 1,
    };
    enum class YearFormat : int32_t
    {
        None = 0,
        Default = 1,
        Abbreviated = 2,
        Full = 3,
    };
    struct IDateTimeFormatter;
    struct IDateTimeFormatter2;
    struct IDateTimeFormatterFactory;
    struct IDateTimeFormatterStatics;
    struct DateTimeFormatter;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::DayFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::HourFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::MonthFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::SecondFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Globalization::DateTimeFormatting::YearFormat>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter> = L"Windows.Globalization.DateTimeFormatting.DateTimeFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::DayFormat> = L"Windows.Globalization.DateTimeFormatting.DayFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat> = L"Windows.Globalization.DateTimeFormatting.DayOfWeekFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::HourFormat> = L"Windows.Globalization.DateTimeFormatting.HourFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat> = L"Windows.Globalization.DateTimeFormatting.MinuteFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::MonthFormat> = L"Windows.Globalization.DateTimeFormatting.MonthFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::SecondFormat> = L"Windows.Globalization.DateTimeFormatting.SecondFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::YearFormat> = L"Windows.Globalization.DateTimeFormatting.YearFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter> = L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatter";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2> = L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory> = L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics> = L"Windows.Globalization.DateTimeFormatting.IDateTimeFormatterStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>{ 0x95EECA10,0x73E0,0x4E4B,{ 0xA1,0x83,0x3D,0x6A,0xD0,0xBA,0x35,0xEC } }; // 95EECA10-73E0-4E4B-A183-3D6AD0BA35EC
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>{ 0x27C91A86,0xBDAA,0x4FD0,{ 0x9E,0x36,0x67,0x1D,0x5A,0xA5,0xEE,0x03 } }; // 27C91A86-BDAA-4FD0-9E36-671D5AA5EE03
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>{ 0xEC8D8A53,0x1A2E,0x412D,{ 0x88,0x15,0x3B,0x74,0x5F,0xB1,0xA2,0xA0 } }; // EC8D8A53-1A2E-412D-8815-3B745FB1A2A0
    template <> inline constexpr guid guid_v<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>{ 0xBFCDE7C0,0xDF4C,0x4A2E,{ 0x90,0x12,0xF4,0x7D,0xAF,0x3F,0x12,0x12 } }; // BFCDE7C0-DF4C-4A2E-9012-F47DAF3F1212
    template <> struct default_interface<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>{ using type = winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter; };
    template <> struct abi<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Languages(void**) noexcept = 0;
            virtual int32_t __stdcall get_GeographicRegion(void**) noexcept = 0;
            virtual int32_t __stdcall get_Calendar(void**) noexcept = 0;
            virtual int32_t __stdcall get_Clock(void**) noexcept = 0;
            virtual int32_t __stdcall get_NumeralSystem(void**) noexcept = 0;
            virtual int32_t __stdcall put_NumeralSystem(void*) noexcept = 0;
            virtual int32_t __stdcall get_Patterns(void**) noexcept = 0;
            virtual int32_t __stdcall get_Template(void**) noexcept = 0;
            virtual int32_t __stdcall Format(int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall get_IncludeYear(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncludeMonth(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncludeDayOfWeek(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncludeDay(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncludeHour(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncludeMinute(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IncludeSecond(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall get_ResolvedGeographicRegion(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FormatUsingTimeZone(int64_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateDateTimeFormatter(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDateTimeFormatterLanguages(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDateTimeFormatterContext(void*, void*, void*, void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDateTimeFormatterDate(int32_t, int32_t, int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDateTimeFormatterTime(int32_t, int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDateTimeFormatterDateTimeLanguages(int32_t, int32_t, int32_t, int32_t, int32_t, int32_t, int32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDateTimeFormatterDateTimeContext(int32_t, int32_t, int32_t, int32_t, int32_t, int32_t, int32_t, void*, void*, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LongDate(void**) noexcept = 0;
            virtual int32_t __stdcall get_LongTime(void**) noexcept = 0;
            virtual int32_t __stdcall get_ShortDate(void**) noexcept = 0;
            virtual int32_t __stdcall get_ShortTime(void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Languages() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) GeographicRegion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Calendar() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Clock() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NumeralSystem() const;
        WINRT_IMPL_AUTO(void) NumeralSystem(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) Patterns() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Template() const;
        WINRT_IMPL_AUTO(hstring) Format(winrt::Windows::Foundation::DateTime const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::YearFormat) IncludeYear() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::MonthFormat) IncludeMonth() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat) IncludeDayOfWeek() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DayFormat) IncludeDay() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::HourFormat) IncludeHour() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat) IncludeMinute() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::SecondFormat) IncludeSecond() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedGeographicRegion() const;
    };
    template <> struct consume<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>
    {
        template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter2
    {
        WINRT_IMPL_AUTO(hstring) Format(winrt::Windows::Foundation::DateTime const& datetime, param::hstring const& timeZoneId) const;
    };
    template <> struct consume<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>
    {
        template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter2<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) CreateDateTimeFormatter(param::hstring const& formatTemplate) const;
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) CreateDateTimeFormatterLanguages(param::hstring const& formatTemplate, param::iterable<hstring> const& languages) const;
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) CreateDateTimeFormatterContext(param::hstring const& formatTemplate, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const;
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) CreateDateTimeFormatterDate(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat) const;
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) CreateDateTimeFormatterTime(winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat) const;
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) CreateDateTimeFormatterDateTimeLanguages(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages) const;
        WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) CreateDateTimeFormatterDateTimeContext(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const;
    };
    template <> struct consume<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>
    {
        template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) LongDate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) LongTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) ShortDate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) ShortTime() const;
    };
    template <> struct consume<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>
    {
        template <typename D> using type = consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>;
    };
}
#endif
