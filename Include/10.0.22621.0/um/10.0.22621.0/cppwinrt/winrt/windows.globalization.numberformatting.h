// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_NumberFormatting_H
#define WINRT_Windows_Globalization_NumberFormatting_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Globalization.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Globalization.NumberFormatting.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter<D>::Currency() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter)->get_Currency(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter<D>::Currency(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter)->put_Currency(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode) consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter2<D>::Mode() const
    {
        winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter2<D>::Mode(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_ICurrencyFormatter2<D>::ApplyRoundingForCurrency(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const& roundingAlgorithm) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2)->ApplyRoundingForCurrency(static_cast<int32_t>(roundingAlgorithm)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter) consume_Windows_Globalization_NumberFormatting_ICurrencyFormatterFactory<D>::CreateCurrencyFormatterCode(param::hstring const& currencyCode) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory)->CreateCurrencyFormatterCode(*(void**)(&currencyCode), &result));
        return winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter) consume_Windows_Globalization_NumberFormatting_ICurrencyFormatterFactory<D>::CreateCurrencyFormatterCodeContext(param::hstring const& currencyCode, param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory)->CreateCurrencyFormatterCodeContext(*(void**)(&currencyCode), *(void**)(&languages), *(void**)(&geographicRegion), &result));
        return winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::DecimalFormatter) consume_Windows_Globalization_NumberFormatting_IDecimalFormatterFactory<D>::CreateDecimalFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory)->CreateDecimalFormatter(*(void**)(&languages), *(void**)(&geographicRegion), &result));
        return winrt::Windows::Globalization::NumberFormatting::DecimalFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm) consume_Windows_Globalization_NumberFormatting_IIncrementNumberRounder<D>::RoundingAlgorithm() const
    {
        winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder)->get_RoundingAlgorithm(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_IIncrementNumberRounder<D>::RoundingAlgorithm(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder)->put_RoundingAlgorithm(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Globalization_NumberFormatting_IIncrementNumberRounder<D>::Increment() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder)->get_Increment(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_IIncrementNumberRounder<D>::Increment(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder)->put_Increment(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatter<D>::Format(int64_t value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatter)->FormatInt(value, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatter<D>::Format(uint64_t value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatter)->FormatUInt(value, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatter<D>::Format(double value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatter)->FormatDouble(value, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatter2<D>::FormatInt(int64_t value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatter2)->FormatInt(value, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatter2<D>::FormatUInt(uint64_t value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatter2)->FormatUInt(value, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatter2<D>::FormatDouble(double value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatter2)->FormatDouble(value, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::Languages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_Languages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::GeographicRegion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_GeographicRegion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::IntegerDigits() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_IntegerDigits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::IntegerDigits(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->put_IntegerDigits(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::FractionDigits() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_FractionDigits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::FractionDigits(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->put_FractionDigits(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::IsGrouped() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_IsGrouped(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::IsGrouped(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->put_IsGrouped(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::IsDecimalPointAlwaysDisplayed() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_IsDecimalPointAlwaysDisplayed(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::IsDecimalPointAlwaysDisplayed(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->put_IsDecimalPointAlwaysDisplayed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::NumeralSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_NumeralSystem(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::NumeralSystem(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->put_NumeralSystem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::ResolvedLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_ResolvedLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumberFormatterOptions<D>::ResolvedGeographicRegion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions)->get_ResolvedGeographicRegion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int64_t>) consume_Windows_Globalization_NumberFormatting_INumberParser<D>::ParseInt(param::hstring const& text) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberParser)->ParseInt(*(void**)(&text), &result));
        return winrt::Windows::Foundation::IReference<int64_t>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint64_t>) consume_Windows_Globalization_NumberFormatting_INumberParser<D>::ParseUInt(param::hstring const& text) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberParser)->ParseUInt(*(void**)(&text), &result));
        return winrt::Windows::Foundation::IReference<uint64_t>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Globalization_NumberFormatting_INumberParser<D>::ParseDouble(param::hstring const& text) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberParser)->ParseDouble(*(void**)(&text), &result));
        return winrt::Windows::Foundation::IReference<double>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_NumberFormatting_INumberRounder<D>::RoundInt32(int32_t value) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounder)->RoundInt32(value, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Globalization_NumberFormatting_INumberRounder<D>::RoundUInt32(uint32_t value) const
    {
        uint32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounder)->RoundUInt32(value, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Globalization_NumberFormatting_INumberRounder<D>::RoundInt64(int64_t value) const
    {
        int64_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounder)->RoundInt64(value, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Globalization_NumberFormatting_INumberRounder<D>::RoundUInt64(uint64_t value) const
    {
        uint64_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounder)->RoundUInt64(value, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Globalization_NumberFormatting_INumberRounder<D>::RoundSingle(float value) const
    {
        float result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounder)->RoundSingle(value, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Globalization_NumberFormatting_INumberRounder<D>::RoundDouble(double value) const
    {
        double result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounder)->RoundDouble(value, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::INumberRounder) consume_Windows_Globalization_NumberFormatting_INumberRounderOption<D>::NumberRounder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounderOption)->get_NumberRounder(&value));
        return winrt::Windows::Globalization::NumberFormatting::INumberRounder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_INumberRounderOption<D>::NumberRounder(winrt::Windows::Globalization::NumberFormatting::INumberRounder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumberRounderOption)->put_NumberRounder(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslator<D>::Languages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator)->get_Languages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslator<D>::ResolvedLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator)->get_ResolvedLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslator<D>::NumeralSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator)->get_NumeralSystem(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslator<D>::NumeralSystem(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator)->put_NumeralSystem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslator<D>::TranslateNumerals(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator)->TranslateNumerals(*(void**)(&value), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator) consume_Windows_Globalization_NumberFormatting_INumeralSystemTranslatorFactory<D>::Create(param::iterable<hstring> const& languages) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory)->Create(*(void**)(&languages), &result));
        return winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::PercentFormatter) consume_Windows_Globalization_NumberFormatting_IPercentFormatterFactory<D>::CreatePercentFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory)->CreatePercentFormatter(*(void**)(&languages), *(void**)(&geographicRegion), &result));
        return winrt::Windows::Globalization::NumberFormatting::PercentFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::PermilleFormatter) consume_Windows_Globalization_NumberFormatting_IPermilleFormatterFactory<D>::CreatePermilleFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory)->CreatePermilleFormatter(*(void**)(&languages), *(void**)(&geographicRegion), &result));
        return winrt::Windows::Globalization::NumberFormatting::PermilleFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_NumberFormatting_ISignedZeroOption<D>::IsZeroSigned() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption)->get_IsZeroSigned(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_ISignedZeroOption<D>::IsZeroSigned(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption)->put_IsZeroSigned(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm) consume_Windows_Globalization_NumberFormatting_ISignificantDigitsNumberRounder<D>::RoundingAlgorithm() const
    {
        winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder)->get_RoundingAlgorithm(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_ISignificantDigitsNumberRounder<D>::RoundingAlgorithm(winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder)->put_RoundingAlgorithm(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Globalization_NumberFormatting_ISignificantDigitsNumberRounder<D>::SignificantDigits() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder)->get_SignificantDigits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_ISignificantDigitsNumberRounder<D>::SignificantDigits(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder)->put_SignificantDigits(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_NumberFormatting_ISignificantDigitsOption<D>::SignificantDigits() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption)->get_SignificantDigits(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_NumberFormatting_ISignificantDigitsOption<D>::SignificantDigits(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption)->put_SignificantDigits(value));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter>
    {
        int32_t __stdcall get_Currency(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Currency());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Currency(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Currency(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2>
    {
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatterMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ApplyRoundingForCurrency(int32_t roundingAlgorithm) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ApplyRoundingForCurrency(*reinterpret_cast<winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const*>(&roundingAlgorithm));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory>
    {
        int32_t __stdcall CreateCurrencyFormatterCode(void* currencyCode, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter>(this->shim().CreateCurrencyFormatterCode(*reinterpret_cast<hstring const*>(&currencyCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCurrencyFormatterCodeContext(void* currencyCode, void* languages, void* geographicRegion, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter>(this->shim().CreateCurrencyFormatterCodeContext(*reinterpret_cast<hstring const*>(&currencyCode), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory>
    {
        int32_t __stdcall CreateDecimalFormatter(void* languages, void* geographicRegion, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::NumberFormatting::DecimalFormatter>(this->shim().CreateDecimalFormatter(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder>
    {
        int32_t __stdcall get_RoundingAlgorithm(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm>(this->shim().RoundingAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RoundingAlgorithm(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoundingAlgorithm(*reinterpret_cast<winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Increment(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Increment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Increment(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Increment(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumberFormatter> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumberFormatter>
    {
        int32_t __stdcall FormatInt(int64_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Format(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FormatUInt(uint64_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Format(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FormatDouble(double value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Format(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumberFormatter2> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumberFormatter2>
    {
        int32_t __stdcall FormatInt(int64_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().FormatInt(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FormatUInt(uint64_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().FormatUInt(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FormatDouble(double value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().FormatDouble(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions>
    {
        int32_t __stdcall get_Languages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GeographicRegion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GeographicRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IntegerDigits(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().IntegerDigits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IntegerDigits(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IntegerDigits(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FractionDigits(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FractionDigits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FractionDigits(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FractionDigits(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsGrouped(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsGrouped());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsGrouped(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsGrouped(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDecimalPointAlwaysDisplayed(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDecimalPointAlwaysDisplayed());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsDecimalPointAlwaysDisplayed(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsDecimalPointAlwaysDisplayed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumeralSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NumeralSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NumeralSystem(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NumeralSystem(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResolvedLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResolvedGeographicRegion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ResolvedGeographicRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumberParser> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumberParser>
    {
        int32_t __stdcall ParseInt(void* text, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IReference<int64_t>>(this->shim().ParseInt(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ParseUInt(void* text, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IReference<uint64_t>>(this->shim().ParseUInt(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ParseDouble(void* text, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().ParseDouble(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumberRounder> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumberRounder>
    {
        int32_t __stdcall RoundInt32(int32_t value, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().RoundInt32(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RoundUInt32(uint32_t value, uint32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<uint32_t>(this->shim().RoundUInt32(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RoundInt64(int64_t value, int64_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int64_t>(this->shim().RoundInt64(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RoundUInt64(uint64_t value, uint64_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<uint64_t>(this->shim().RoundUInt64(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RoundSingle(float value, float* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<float>(this->shim().RoundSingle(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RoundDouble(double value, double* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<double>(this->shim().RoundDouble(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumberRounderOption> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumberRounderOption>
    {
        int32_t __stdcall get_NumberRounder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::NumberFormatting::INumberRounder>(this->shim().NumberRounder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NumberRounder(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NumberRounder(*reinterpret_cast<winrt::Windows::Globalization::NumberFormatting::INumberRounder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator>
    {
        int32_t __stdcall get_Languages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResolvedLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumeralSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NumeralSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NumeralSystem(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NumeralSystem(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TranslateNumerals(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().TranslateNumerals(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory>
    {
        int32_t __stdcall Create(void* languages, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory>
    {
        int32_t __stdcall CreatePercentFormatter(void* languages, void* geographicRegion, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::NumberFormatting::PercentFormatter>(this->shim().CreatePercentFormatter(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory>
    {
        int32_t __stdcall CreatePermilleFormatter(void* languages, void* geographicRegion, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::NumberFormatting::PermilleFormatter>(this->shim().CreatePermilleFormatter(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption>
    {
        int32_t __stdcall get_IsZeroSigned(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsZeroSigned());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsZeroSigned(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsZeroSigned(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder>
    {
        int32_t __stdcall get_RoundingAlgorithm(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm>(this->shim().RoundingAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RoundingAlgorithm(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoundingAlgorithm(*reinterpret_cast<winrt::Windows::Globalization::NumberFormatting::RoundingAlgorithm const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SignificantDigits(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SignificantDigits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SignificantDigits(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignificantDigits(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption> : produce_base<D, winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption>
    {
        int32_t __stdcall get_SignificantDigits(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SignificantDigits());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SignificantDigits(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SignificantDigits(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
}
WINRT_EXPORT namespace winrt::Windows::Globalization::NumberFormatting
{
    inline CurrencyFormatter::CurrencyFormatter(param::hstring const& currencyCode) :
        CurrencyFormatter(impl::call_factory<CurrencyFormatter, ICurrencyFormatterFactory>([&](ICurrencyFormatterFactory const& f) { return f.CreateCurrencyFormatterCode(currencyCode); }))
    {
    }
    inline CurrencyFormatter::CurrencyFormatter(param::hstring const& currencyCode, param::iterable<hstring> const& languages, param::hstring const& geographicRegion) :
        CurrencyFormatter(impl::call_factory<CurrencyFormatter, ICurrencyFormatterFactory>([&](ICurrencyFormatterFactory const& f) { return f.CreateCurrencyFormatterCodeContext(currencyCode, languages, geographicRegion); }))
    {
    }
    inline DecimalFormatter::DecimalFormatter() :
        DecimalFormatter(impl::call_factory_cast<DecimalFormatter(*)(winrt::Windows::Foundation::IActivationFactory const&), DecimalFormatter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DecimalFormatter>(); }))
    {
    }
    inline DecimalFormatter::DecimalFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) :
        DecimalFormatter(impl::call_factory<DecimalFormatter, IDecimalFormatterFactory>([&](IDecimalFormatterFactory const& f) { return f.CreateDecimalFormatter(languages, geographicRegion); }))
    {
    }
    inline IncrementNumberRounder::IncrementNumberRounder() :
        IncrementNumberRounder(impl::call_factory_cast<IncrementNumberRounder(*)(winrt::Windows::Foundation::IActivationFactory const&), IncrementNumberRounder>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<IncrementNumberRounder>(); }))
    {
    }
    inline NumeralSystemTranslator::NumeralSystemTranslator() :
        NumeralSystemTranslator(impl::call_factory_cast<NumeralSystemTranslator(*)(winrt::Windows::Foundation::IActivationFactory const&), NumeralSystemTranslator>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<NumeralSystemTranslator>(); }))
    {
    }
    inline NumeralSystemTranslator::NumeralSystemTranslator(param::iterable<hstring> const& languages) :
        NumeralSystemTranslator(impl::call_factory<NumeralSystemTranslator, INumeralSystemTranslatorFactory>([&](INumeralSystemTranslatorFactory const& f) { return f.Create(languages); }))
    {
    }
    inline PercentFormatter::PercentFormatter() :
        PercentFormatter(impl::call_factory_cast<PercentFormatter(*)(winrt::Windows::Foundation::IActivationFactory const&), PercentFormatter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PercentFormatter>(); }))
    {
    }
    inline PercentFormatter::PercentFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) :
        PercentFormatter(impl::call_factory<PercentFormatter, IPercentFormatterFactory>([&](IPercentFormatterFactory const& f) { return f.CreatePercentFormatter(languages, geographicRegion); }))
    {
    }
    inline PermilleFormatter::PermilleFormatter() :
        PermilleFormatter(impl::call_factory_cast<PermilleFormatter(*)(winrt::Windows::Foundation::IActivationFactory const&), PermilleFormatter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PermilleFormatter>(); }))
    {
    }
    inline PermilleFormatter::PermilleFormatter(param::iterable<hstring> const& languages, param::hstring const& geographicRegion) :
        PermilleFormatter(impl::call_factory<PermilleFormatter, IPermilleFormatterFactory>([&](IPermilleFormatterFactory const& f) { return f.CreatePermilleFormatter(languages, geographicRegion); }))
    {
    }
    inline SignificantDigitsNumberRounder::SignificantDigitsNumberRounder() :
        SignificantDigitsNumberRounder(impl::call_factory_cast<SignificantDigitsNumberRounder(*)(winrt::Windows::Foundation::IActivationFactory const&), SignificantDigitsNumberRounder>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SignificantDigitsNumberRounder>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::ICurrencyFormatterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::IDecimalFormatterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::IIncrementNumberRounder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumberFormatter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumberFormatter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumberFormatterOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumberParser> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumberRounder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumberRounderOption> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::INumeralSystemTranslatorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::IPercentFormatterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::IPermilleFormatterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::ISignedZeroOption> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsNumberRounder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::ISignificantDigitsOption> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::CurrencyFormatter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::DecimalFormatter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::IncrementNumberRounder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::NumeralSystemTranslator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::PercentFormatter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::PermilleFormatter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumberFormatting::SignificantDigitsNumberRounder> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
