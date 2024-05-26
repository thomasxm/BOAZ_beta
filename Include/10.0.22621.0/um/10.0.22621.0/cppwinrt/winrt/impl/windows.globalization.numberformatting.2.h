// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_NumberFormatting_2_H
#define WINRT_Windows_Globalization_NumberFormatting_2_H
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Globalization.NumberFormatting.1.h"
WINRT_EXPORT namespace winrt::Windows::Globalization::NumberFormatting
{
    struct __declspec(empty_bases) CurrencyFormatter : winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter,
        impl::require<CurrencyFormatter, winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption, winrt::Windows::Globalization::NumberFormatting::INumberRounderOption, winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>
    {
        CurrencyFormatter(std::nullptr_t) noexcept {}
        CurrencyFormatter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter(ptr, take_ownership_from_abi) {}
        explicit CurrencyFormatter(param::hstring const& currencyCode);
        CurrencyFormatter(param::hstring const& currencyCode, param::iterable<hstring> const& languages, param::hstring const& geographicRegion);
    };
    struct __declspec(empty_bases) DecimalFormatter : winrt::Windows::Globalization::NumberFormatting::INumberFormatter,
        impl::require<DecimalFormatter, winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions, winrt::Windows::Globalization::NumberFormatting::INumberFormatter2, winrt::Windows::Globalization::NumberFormatting::INumberParser, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption, winrt::Windows::Globalization::NumberFormatting::INumberRounderOption, winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>
    {
        DecimalFormatter(std::nullptr_t) noexcept {}
        DecimalFormatter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Globalization::NumberFormatting::INumberFormatter(ptr, take_ownership_from_abi) {}
        DecimalFormatter();
        DecimalFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion);
    };
    struct __declspec(empty_bases) IncrementNumberRounder : winrt::Windows::Globalization::NumberFormatting::INumberRounder,
        impl::require<IncrementNumberRounder, winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder>
    {
        IncrementNumberRounder(std::nullptr_t) noexcept {}
        IncrementNumberRounder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Globalization::NumberFormatting::INumberRounder(ptr, take_ownership_from_abi) {}
        IncrementNumberRounder();
    };
    struct __declspec(empty_bases) NumeralSystemTranslator : winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator
    {
        NumeralSystemTranslator(std::nullptr_t) noexcept {}
        NumeralSystemTranslator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator(ptr, take_ownership_from_abi) {}
        NumeralSystemTranslator();
        explicit NumeralSystemTranslator(param::iterable<hstring> const& languages);
    };
    struct __declspec(empty_bases) PercentFormatter : winrt::Windows::Globalization::NumberFormatting::INumberFormatter,
        impl::require<PercentFormatter, winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions, winrt::Windows::Globalization::NumberFormatting::INumberFormatter2, winrt::Windows::Globalization::NumberFormatting::INumberParser, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption, winrt::Windows::Globalization::NumberFormatting::INumberRounderOption, winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>
    {
        PercentFormatter(std::nullptr_t) noexcept {}
        PercentFormatter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Globalization::NumberFormatting::INumberFormatter(ptr, take_ownership_from_abi) {}
        PercentFormatter();
        PercentFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion);
    };
    struct __declspec(empty_bases) PermilleFormatter : winrt::Windows::Globalization::NumberFormatting::INumberFormatter,
        impl::require<PermilleFormatter, winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions, winrt::Windows::Globalization::NumberFormatting::INumberFormatter2, winrt::Windows::Globalization::NumberFormatting::INumberParser, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption, winrt::Windows::Globalization::NumberFormatting::INumberRounderOption, winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>
    {
        PermilleFormatter(std::nullptr_t) noexcept {}
        PermilleFormatter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Globalization::NumberFormatting::INumberFormatter(ptr, take_ownership_from_abi) {}
        PermilleFormatter();
        PermilleFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion);
    };
    struct __declspec(empty_bases) SignificantDigitsNumberRounder : winrt::Windows::Globalization::NumberFormatting::INumberRounder,
        impl::require<SignificantDigitsNumberRounder, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder>
    {
        SignificantDigitsNumberRounder(std::nullptr_t) noexcept {}
        SignificantDigitsNumberRounder(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Globalization::NumberFormatting::INumberRounder(ptr, take_ownership_from_abi) {}
        SignificantDigitsNumberRounder();
    };
}
#endif
