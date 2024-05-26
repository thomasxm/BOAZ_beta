// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_H
#define WINRT_Windows_Globalization_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IApplicationLanguagesStatics<D>::PrimaryLanguageOverride() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IApplicationLanguagesStatics)->get_PrimaryLanguageOverride(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_IApplicationLanguagesStatics<D>::PrimaryLanguageOverride(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IApplicationLanguagesStatics)->put_PrimaryLanguageOverride(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_IApplicationLanguagesStatics<D>::Languages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IApplicationLanguagesStatics)->get_Languages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_IApplicationLanguagesStatics<D>::ManifestLanguages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IApplicationLanguagesStatics)->get_ManifestLanguages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_IApplicationLanguagesStatics2<D>::GetLanguagesForUser(winrt::Windows::System::User const& user) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IApplicationLanguagesStatics2)->GetLanguagesForUser(*(void**)(&user), &value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Calendar) consume_Windows_Globalization_ICalendar<D>::Clone() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->Clone(&value));
        return winrt::Windows::Globalization::Calendar{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::SetToMin() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->SetToMin());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::SetToMax() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->SetToMax());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_ICalendar<D>::Languages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Languages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::NumeralSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumeralSystem(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::NumeralSystem(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_NumeralSystem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::GetCalendarSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->GetCalendarSystem(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::ChangeCalendarSystem(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->ChangeCalendarSystem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::GetClock() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->GetClock(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::ChangeClock(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->ChangeClock(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Globalization_ICalendar<D>::GetDateTime() const
    {
        winrt::Windows::Foundation::DateTime result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->GetDateTime(put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::SetDateTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->SetDateTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::SetToNow() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->SetToNow());
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstEra() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstEra(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastEra() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastEra(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfEras() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfEras(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Era() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Era(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Era(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Era(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddEras(int32_t eras) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddEras(eras));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::EraAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->EraAsFullString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::EraAsString(int32_t idealLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->EraAsString(idealLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstYearInThisEra() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstYearInThisEra(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastYearInThisEra() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastYearInThisEra(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfYearsInThisEra() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfYearsInThisEra(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Year() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Year(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Year(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Year(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddYears(int32_t years) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddYears(years));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::YearAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->YearAsString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::YearAsTruncatedString(int32_t remainingDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->YearAsTruncatedString(remainingDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::YearAsPaddedString(int32_t minDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->YearAsPaddedString(minDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstMonthInThisYear() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstMonthInThisYear(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastMonthInThisYear() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastMonthInThisYear(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfMonthsInThisYear() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfMonthsInThisYear(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Month() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Month(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Month(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Month(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddMonths(int32_t months) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddMonths(months));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MonthAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MonthAsFullString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MonthAsString(int32_t idealLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MonthAsString(idealLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MonthAsSoloString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MonthAsFullSoloString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MonthAsSoloString(int32_t idealLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MonthAsSoloString(idealLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MonthAsNumericString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MonthAsNumericString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MonthAsPaddedNumericString(int32_t minDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MonthAsPaddedNumericString(minDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddWeeks(int32_t weeks) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddWeeks(weeks));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstDayInThisMonth() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstDayInThisMonth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastDayInThisMonth() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastDayInThisMonth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfDaysInThisMonth() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfDaysInThisMonth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Day() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Day(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Day(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Day(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddDays(int32_t days) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddDays(days));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::DayAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->DayAsString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::DayAsPaddedString(int32_t minDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->DayAsPaddedString(minDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DayOfWeek) consume_Windows_Globalization_ICalendar<D>::DayOfWeek() const
    {
        winrt::Windows::Globalization::DayOfWeek value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_DayOfWeek(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->DayOfWeekAsFullString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsString(int32_t idealLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->DayOfWeekAsString(idealLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsSoloString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->DayOfWeekAsFullSoloString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::DayOfWeekAsSoloString(int32_t idealLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->DayOfWeekAsSoloString(idealLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstPeriodInThisDay() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstPeriodInThisDay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastPeriodInThisDay() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastPeriodInThisDay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfPeriodsInThisDay() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfPeriodsInThisDay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Period() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Period(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Period(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Period(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddPeriods(int32_t periods) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddPeriods(periods));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::PeriodAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->PeriodAsFullString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::PeriodAsString(int32_t idealLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->PeriodAsString(idealLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstHourInThisPeriod() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstHourInThisPeriod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastHourInThisPeriod() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastHourInThisPeriod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfHoursInThisPeriod() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfHoursInThisPeriod(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Hour() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Hour(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Hour(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Hour(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddHours(int32_t hours) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddHours(hours));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::HourAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->HourAsString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::HourAsPaddedString(int32_t minDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->HourAsPaddedString(minDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Minute() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Minute(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Minute(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Minute(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddMinutes(int32_t minutes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddMinutes(minutes));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MinuteAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MinuteAsString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::MinuteAsPaddedString(int32_t minDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->MinuteAsPaddedString(minDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Second() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Second(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Second(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Second(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddSeconds(int32_t seconds) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddSeconds(seconds));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::SecondAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->SecondAsString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::SecondAsPaddedString(int32_t minDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->SecondAsPaddedString(minDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Nanosecond() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_Nanosecond(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::Nanosecond(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->put_Nanosecond(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::AddNanoseconds(int32_t nanoseconds) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->AddNanoseconds(nanoseconds));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::NanosecondAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->NanosecondAsString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::NanosecondAsPaddedString(int32_t minDigits) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->NanosecondAsPaddedString(minDigits, &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::Compare(winrt::Windows::Globalization::Calendar const& other) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->Compare(*(void**)(&other), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::CompareDateTime(winrt::Windows::Foundation::DateTime const& other) const
    {
        int32_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->CompareDateTime(impl::bind_in(other), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ICalendar<D>::CopyTo(winrt::Windows::Globalization::Calendar const& other) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->CopyTo(*(void**)(&other)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstMinuteInThisHour() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstMinuteInThisHour(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastMinuteInThisHour() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastMinuteInThisHour(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfMinutesInThisHour() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfMinutesInThisHour(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::FirstSecondInThisMinute() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_FirstSecondInThisMinute(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::LastSecondInThisMinute() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_LastSecondInThisMinute(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Globalization_ICalendar<D>::NumberOfSecondsInThisMinute() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_NumberOfSecondsInThisMinute(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendar<D>::ResolvedLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_ResolvedLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_ICalendar<D>::IsDaylightSavingTime() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendar)->get_IsDaylightSavingTime(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Calendar) consume_Windows_Globalization_ICalendarFactory<D>::CreateCalendarDefaultCalendarAndClock(param::iterable<hstring> const& languages) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarFactory)->CreateCalendarDefaultCalendarAndClock(*(void**)(&languages), &result));
        return winrt::Windows::Globalization::Calendar{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Calendar) consume_Windows_Globalization_ICalendarFactory<D>::CreateCalendar(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarFactory)->CreateCalendar(*(void**)(&languages), *(void**)(&calendar), *(void**)(&clock), &result));
        return winrt::Windows::Globalization::Calendar{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Calendar) consume_Windows_Globalization_ICalendarFactory2<D>::CreateCalendarWithTimeZone(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock, param::hstring const& timeZoneId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarFactory2)->CreateCalendarWithTimeZone(*(void**)(&languages), *(void**)(&calendar), *(void**)(&clock), *(void**)(&timeZoneId), &result));
        return winrt::Windows::Globalization::Calendar{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Gregorian() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Gregorian(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Hebrew() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Hebrew(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Hijri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Hijri(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Japanese() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Japanese(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Julian() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Julian(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Korean() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Korean(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Taiwan() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Taiwan(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::Thai() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_Thai(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics<D>::UmAlQura() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics)->get_UmAlQura(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics2<D>::Persian() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics2)->get_Persian(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::ChineseLunar() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics3)->get_ChineseLunar(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::JapaneseLunar() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics3)->get_JapaneseLunar(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::KoreanLunar() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics3)->get_KoreanLunar(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::TaiwanLunar() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics3)->get_TaiwanLunar(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICalendarIdentifiersStatics3<D>::VietnameseLunar() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICalendarIdentifiersStatics3)->get_VietnameseLunar(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IClockIdentifiersStatics<D>::TwelveHour() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IClockIdentifiersStatics)->get_TwelveHour(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IClockIdentifiersStatics<D>::TwentyFourHour() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IClockIdentifiersStatics)->get_TwentyFourHour(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyAmount<D>::Amount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyAmount)->get_Amount(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyAmount<D>::Currency() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyAmount)->get_Currency(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::CurrencyAmount) consume_Windows_Globalization_ICurrencyAmountFactory<D>::Create(param::hstring const& amount, param::hstring const& currency) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyAmountFactory)->Create(*(void**)(&amount), *(void**)(&currency), &result));
        return winrt::Windows::Globalization::CurrencyAmount{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AED() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_AED(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AFN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_AFN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ALL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ALL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AMD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_AMD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ANG() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ANG(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AOA() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_AOA(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ARS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ARS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AUD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_AUD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AWG() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_AWG(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::AZN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_AZN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BAM() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BAM(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BBD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BBD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BDT() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BDT(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BGN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BGN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BHD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BHD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BIF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BIF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BMD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BMD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BND() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BND(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BOB() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BOB(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BRL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BRL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BSD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BSD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BTN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BTN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BWP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BWP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BYR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BYR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::BZD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_BZD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CAD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CAD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CDF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CDF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CHF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CHF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CLP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CLP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CNY() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CNY(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::COP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_COP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CRC() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CRC(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CUP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CUP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CVE() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CVE(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::CZK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_CZK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DJF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_DJF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DKK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_DKK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DOP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_DOP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::DZD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_DZD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::EGP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_EGP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ERN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ERN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ETB() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ETB(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::EUR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_EUR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::FJD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_FJD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::FKP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_FKP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GBP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GBP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GEL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GEL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GHS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GHS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GIP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GIP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GMD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GMD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GNF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GNF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GTQ() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GTQ(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::GYD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_GYD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HKD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_HKD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HNL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_HNL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HRK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_HRK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HTG() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_HTG(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::HUF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_HUF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::IDR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_IDR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ILS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ILS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::INR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_INR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::IQD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_IQD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::IRR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_IRR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ISK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ISK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::JMD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_JMD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::JOD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_JOD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::JPY() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_JPY(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KES() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KES(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KGS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KGS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KHR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KHR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KMF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KMF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KPW() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KPW(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KRW() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KRW(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KWD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KWD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KYD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KYD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::KZT() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_KZT(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LAK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LAK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LBP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LBP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LKR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LKR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LRD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LRD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LSL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LSL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LTL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LTL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LVL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LVL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::LYD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_LYD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MAD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MAD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MDL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MDL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MGA() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MGA(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MKD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MKD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MMK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MMK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MNT() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MNT(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MOP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MOP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MRO() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MRO(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MUR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MUR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MVR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MVR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MWK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MWK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MXN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MXN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MYR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MYR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::MZN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_MZN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NAD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_NAD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NGN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_NGN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NIO() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_NIO(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NOK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_NOK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NPR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_NPR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::NZD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_NZD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::OMR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_OMR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PAB() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_PAB(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PEN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_PEN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PGK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_PGK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PHP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_PHP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PKR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_PKR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PLN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_PLN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::PYG() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_PYG(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::QAR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_QAR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RON() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_RON(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RSD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_RSD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RUB() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_RUB(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::RWF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_RWF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SAR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SAR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SBD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SBD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SCR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SCR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SDG() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SDG(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SEK() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SEK(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SGD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SGD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SHP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SHP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SLL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SLL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SOS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SOS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SRD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SRD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::STD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_STD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SYP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SYP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::SZL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_SZL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::THB() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_THB(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TJS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TJS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TMT() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TMT(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TND() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TND(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TOP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TOP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TRY() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TRY(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TTD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TTD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TWD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TWD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::TZS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_TZS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UAH() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_UAH(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UGX() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_UGX(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::USD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_USD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UYU() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_UYU(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::UZS() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_UZS(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::VEF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_VEF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::VND() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_VND(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::VUV() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_VUV(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::WST() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_WST(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XAF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_XAF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XCD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_XCD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XOF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_XOF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XPF() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_XPF(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::XXX() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_XXX(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::YER() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_YER(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ZAR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ZAR(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ZMW() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ZMW(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics<D>::ZWL() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics)->get_ZWL(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics2<D>::BYN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics2)->get_BYN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::MRU() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics3)->get_MRU(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::SSP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics3)->get_SSP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::STN() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics3)->get_STN(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ICurrencyIdentifiersStatics3<D>::VES() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ICurrencyIdentifiersStatics3)->get_VES(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IGeographicRegion<D>::Code() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegion)->get_Code(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IGeographicRegion<D>::CodeTwoLetter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegion)->get_CodeTwoLetter(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IGeographicRegion<D>::CodeThreeLetter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegion)->get_CodeThreeLetter(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IGeographicRegion<D>::CodeThreeDigit() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegion)->get_CodeThreeDigit(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IGeographicRegion<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegion)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IGeographicRegion<D>::NativeName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegion)->get_NativeName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_IGeographicRegion<D>::CurrenciesInUse() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegion)->get_CurrenciesInUse(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::GeographicRegion) consume_Windows_Globalization_IGeographicRegionFactory<D>::CreateGeographicRegion(param::hstring const& geographicRegionCode) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegionFactory)->CreateGeographicRegion(*(void**)(&geographicRegionCode), &result));
        return winrt::Windows::Globalization::GeographicRegion{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_IGeographicRegionStatics<D>::IsSupported(param::hstring const& geographicRegionCode) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IGeographicRegionStatics)->IsSupported(*(void**)(&geographicRegionCode), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IJapanesePhoneme<D>::DisplayText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IJapanesePhoneme)->get_DisplayText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_IJapanesePhoneme<D>::YomiText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IJapanesePhoneme)->get_YomiText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_IJapanesePhoneme<D>::IsPhraseStart() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IJapanesePhoneme)->get_IsPhraseStart(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::JapanesePhoneme>) consume_Windows_Globalization_IJapanesePhoneticAnalyzerStatics<D>::GetWords(param::hstring const& input) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IJapanesePhoneticAnalyzerStatics)->GetWords(*(void**)(&input), &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::JapanesePhoneme>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::JapanesePhoneme>) consume_Windows_Globalization_IJapanesePhoneticAnalyzerStatics<D>::GetWords(param::hstring const& input, bool monoRuby) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::IJapanesePhoneticAnalyzerStatics)->GetWordsWithMonoRubyOption(*(void**)(&input), monoRuby, &result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::JapanesePhoneme>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ILanguage<D>::LanguageTag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguage)->get_LanguageTag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ILanguage<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguage)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ILanguage<D>::NativeName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguage)->get_NativeName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ILanguage<D>::Script() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguage)->get_Script(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::LanguageLayoutDirection) consume_Windows_Globalization_ILanguage2<D>::LayoutDirection() const
    {
        winrt::Windows::Globalization::LanguageLayoutDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguage2)->get_LayoutDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ILanguage3<D>::AbbreviatedName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguage3)->get_AbbreviatedName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_ILanguageExtensionSubtags<D>::GetExtensionSubtags(param::hstring const& singleton) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguageExtensionSubtags)->GetExtensionSubtags(*(void**)(&singleton), &value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Language) consume_Windows_Globalization_ILanguageFactory<D>::CreateLanguage(param::hstring const& languageTag) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguageFactory)->CreateLanguage(*(void**)(&languageTag), &result));
        return winrt::Windows::Globalization::Language{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_ILanguageStatics<D>::IsWellFormed(param::hstring const& languageTag) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguageStatics)->IsWellFormed(*(void**)(&languageTag), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ILanguageStatics<D>::CurrentInputMethodLanguageTag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguageStatics)->get_CurrentInputMethodLanguageTag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Globalization_ILanguageStatics2<D>::TrySetInputMethodLanguageTag(param::hstring const& languageTag) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguageStatics2)->TrySetInputMethodLanguageTag(*(void**)(&languageTag), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Globalization_ILanguageStatics3<D>::GetMuiCompatibleLanguageListFromLanguageTags(param::iterable<hstring> const& languageTags) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ILanguageStatics3)->GetMuiCompatibleLanguageListFromLanguageTags(*(void**)(&languageTags), &result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Arab() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Arab(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::ArabExt() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_ArabExt(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Bali() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Bali(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Beng() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Beng(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Cham() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Cham(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Deva() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Deva(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::FullWide() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_FullWide(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Gujr() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Gujr(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Guru() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Guru(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::HaniDec() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_HaniDec(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Java() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Java(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Kali() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Kali(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Khmr() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Khmr(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Knda() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Knda(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Lana() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Lana(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::LanaTham() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_LanaTham(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Laoo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Laoo(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Latn() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Latn(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Lepc() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Lepc(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Limb() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Limb(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mlym() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mlym(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mong() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mong(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mtei() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mtei(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Mymr() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Mymr(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::MymrShan() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_MymrShan(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Nkoo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Nkoo(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Olck() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Olck(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Orya() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Orya(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Saur() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Saur(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Sund() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Sund(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Talu() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Talu(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::TamlDec() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_TamlDec(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Telu() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Telu(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Thai() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Thai(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Tibt() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Tibt(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics<D>::Vaii() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics)->get_Vaii(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::Brah() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_Brah(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::Osma() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_Osma(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathBold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathBold(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathDbl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathDbl(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathSans() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathSans(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathSanb() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathSanb(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::MathMono() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_MathMono(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthBold() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthBold(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthDbl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthDbl(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthSans() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthSans(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthSanb() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthSanb(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_INumeralSystemIdentifiersStatics2<D>::ZmthMono() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2)->get_ZmthMono(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ITimeZoneOnCalendar<D>::GetTimeZone() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ITimeZoneOnCalendar)->GetTimeZone(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_ITimeZoneOnCalendar<D>::ChangeTimeZone(param::hstring const& timeZoneId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ITimeZoneOnCalendar)->ChangeTimeZone(*(void**)(&timeZoneId)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ITimeZoneOnCalendar<D>::TimeZoneAsString() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ITimeZoneOnCalendar)->TimeZoneAsFullString(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_ITimeZoneOnCalendar<D>::TimeZoneAsString(int32_t idealLength) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::ITimeZoneOnCalendar)->TimeZoneAsString(idealLength, &result));
        return hstring{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IApplicationLanguagesStatics> : produce_base<D, winrt::Windows::Globalization::IApplicationLanguagesStatics>
    {
        int32_t __stdcall get_PrimaryLanguageOverride(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PrimaryLanguageOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PrimaryLanguageOverride(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrimaryLanguageOverride(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Languages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ManifestLanguages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().ManifestLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IApplicationLanguagesStatics2> : produce_base<D, winrt::Windows::Globalization::IApplicationLanguagesStatics2>
    {
        int32_t __stdcall GetLanguagesForUser(void* user, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetLanguagesForUser(*reinterpret_cast<winrt::Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICalendar> : produce_base<D, winrt::Windows::Globalization::ICalendar>
    {
        int32_t __stdcall Clone(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::Calendar>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetToMin() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetToMin();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetToMax() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetToMax();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Languages(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Languages());
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
        int32_t __stdcall GetCalendarSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetCalendarSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ChangeCalendarSystem(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChangeCalendarSystem(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetClock(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetClock());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ChangeClock(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChangeClock(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDateTime(int64_t* result) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().GetDateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDateTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDateTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetToNow() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetToNow();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstEra(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastEra(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfEras(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfEras());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Era(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Era());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Era(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Era(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddEras(int32_t eras) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddEras(eras);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EraAsFullString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().EraAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EraAsString(int32_t idealLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().EraAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstYearInThisEra(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstYearInThisEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastYearInThisEra(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastYearInThisEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfYearsInThisEra(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfYearsInThisEra());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Year(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Year(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Year(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddYears(int32_t years) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddYears(years);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall YearAsString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().YearAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall YearAsTruncatedString(int32_t remainingDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().YearAsTruncatedString(remainingDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall YearAsPaddedString(int32_t minDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().YearAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstMonthInThisYear(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstMonthInThisYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastMonthInThisYear(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastMonthInThisYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfMonthsInThisYear(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfMonthsInThisYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Month(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Month());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Month(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Month(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddMonths(int32_t months) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddMonths(months);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MonthAsFullString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MonthAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MonthAsString(int32_t idealLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MonthAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MonthAsFullSoloString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MonthAsSoloString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MonthAsSoloString(int32_t idealLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MonthAsSoloString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MonthAsNumericString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MonthAsNumericString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MonthAsPaddedNumericString(int32_t minDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MonthAsPaddedNumericString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddWeeks(int32_t weeks) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddWeeks(weeks);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstDayInThisMonth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstDayInThisMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastDayInThisMonth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastDayInThisMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfDaysInThisMonth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfDaysInThisMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Day(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Day());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Day(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Day(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddDays(int32_t days) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddDays(days);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DayAsString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().DayAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DayAsPaddedString(int32_t minDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().DayAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DayOfWeek(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DayOfWeek>(this->shim().DayOfWeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DayOfWeekAsFullString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().DayOfWeekAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DayOfWeekAsString(int32_t idealLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().DayOfWeekAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DayOfWeekAsFullSoloString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().DayOfWeekAsSoloString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DayOfWeekAsSoloString(int32_t idealLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().DayOfWeekAsSoloString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstPeriodInThisDay(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstPeriodInThisDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastPeriodInThisDay(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastPeriodInThisDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfPeriodsInThisDay(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfPeriodsInThisDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Period(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Period());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Period(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Period(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddPeriods(int32_t periods) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddPeriods(periods);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PeriodAsFullString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().PeriodAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PeriodAsString(int32_t idealLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().PeriodAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstHourInThisPeriod(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstHourInThisPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastHourInThisPeriod(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastHourInThisPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfHoursInThisPeriod(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfHoursInThisPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hour(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Hour());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Hour(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Hour(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddHours(int32_t hours) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddHours(hours);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HourAsString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().HourAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HourAsPaddedString(int32_t minDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().HourAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Minute(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Minute());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Minute(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Minute(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddMinutes(int32_t minutes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddMinutes(minutes);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MinuteAsString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MinuteAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MinuteAsPaddedString(int32_t minDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().MinuteAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Second(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Second());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Second(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Second(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSeconds(int32_t seconds) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddSeconds(seconds);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SecondAsString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().SecondAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SecondAsPaddedString(int32_t minDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().SecondAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Nanosecond(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Nanosecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Nanosecond(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Nanosecond(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddNanoseconds(int32_t nanoseconds) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddNanoseconds(nanoseconds);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NanosecondAsString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().NanosecondAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NanosecondAsPaddedString(int32_t minDigits, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().NanosecondAsPaddedString(minDigits));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Compare(void* other, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().Compare(*reinterpret_cast<winrt::Windows::Globalization::Calendar const*>(&other)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CompareDateTime(int64_t other, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<int32_t>(this->shim().CompareDateTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&other)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyTo(void* other) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CopyTo(*reinterpret_cast<winrt::Windows::Globalization::Calendar const*>(&other));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstMinuteInThisHour(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstMinuteInThisHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastMinuteInThisHour(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastMinuteInThisHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfMinutesInThisHour(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfMinutesInThisHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstSecondInThisMinute(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().FirstSecondInThisMinute());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastSecondInThisMinute(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LastSecondInThisMinute());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NumberOfSecondsInThisMinute(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().NumberOfSecondsInThisMinute());
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
        int32_t __stdcall get_IsDaylightSavingTime(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDaylightSavingTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICalendarFactory> : produce_base<D, winrt::Windows::Globalization::ICalendarFactory>
    {
        int32_t __stdcall CreateCalendarDefaultCalendarAndClock(void* languages, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::Calendar>(this->shim().CreateCalendarDefaultCalendarAndClock(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCalendar(void* languages, void* calendar, void* clock, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::Calendar>(this->shim().CreateCalendar(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICalendarFactory2> : produce_base<D, winrt::Windows::Globalization::ICalendarFactory2>
    {
        int32_t __stdcall CreateCalendarWithTimeZone(void* languages, void* calendar, void* clock, void* timeZoneId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::Calendar>(this->shim().CreateCalendarWithTimeZone(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock), *reinterpret_cast<hstring const*>(&timeZoneId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICalendarIdentifiersStatics> : produce_base<D, winrt::Windows::Globalization::ICalendarIdentifiersStatics>
    {
        int32_t __stdcall get_Gregorian(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Gregorian());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hebrew(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Hebrew());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hijri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Hijri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Japanese(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Japanese());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Julian(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Julian());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Korean(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Korean());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Taiwan(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Taiwan());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thai(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Thai());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UmAlQura(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UmAlQura());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICalendarIdentifiersStatics2> : produce_base<D, winrt::Windows::Globalization::ICalendarIdentifiersStatics2>
    {
        int32_t __stdcall get_Persian(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Persian());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICalendarIdentifiersStatics3> : produce_base<D, winrt::Windows::Globalization::ICalendarIdentifiersStatics3>
    {
        int32_t __stdcall get_ChineseLunar(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ChineseLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JapaneseLunar(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().JapaneseLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KoreanLunar(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KoreanLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TaiwanLunar(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TaiwanLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VietnameseLunar(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VietnameseLunar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IClockIdentifiersStatics> : produce_base<D, winrt::Windows::Globalization::IClockIdentifiersStatics>
    {
        int32_t __stdcall get_TwelveHour(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TwelveHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TwentyFourHour(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TwentyFourHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICurrencyAmount> : produce_base<D, winrt::Windows::Globalization::ICurrencyAmount>
    {
        int32_t __stdcall get_Amount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Amount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Currency(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Currency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICurrencyAmountFactory> : produce_base<D, winrt::Windows::Globalization::ICurrencyAmountFactory>
    {
        int32_t __stdcall Create(void* amount, void* currency, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::CurrencyAmount>(this->shim().Create(*reinterpret_cast<hstring const*>(&amount), *reinterpret_cast<hstring const*>(&currency)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICurrencyIdentifiersStatics> : produce_base<D, winrt::Windows::Globalization::ICurrencyIdentifiersStatics>
    {
        int32_t __stdcall get_AED(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AED());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AFN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AFN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ALL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ALL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AMD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ANG(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ANG());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AOA(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AOA());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ARS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ARS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AUD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AUD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AWG(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AWG());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AZN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AZN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BAM(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BAM());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BBD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BBD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BDT(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BDT());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BGN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BGN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BHD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BHD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BIF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BIF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BMD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BND(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BND());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BOB(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BOB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BRL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BRL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BSD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BSD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BTN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BTN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BWP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BWP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BYR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BYR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BZD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BZD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CAD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CAD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CDF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CDF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CHF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CHF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CLP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CLP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CNY(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CNY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_COP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().COP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CRC(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CRC());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CUP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CUP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CVE(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CVE());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CZK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CZK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DJF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DJF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DKK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DKK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DOP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DOP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DZD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DZD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EGP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EGP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ERN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ERN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ETB(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ETB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EUR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EUR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FJD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FJD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FKP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FKP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GBP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GBP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GEL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GEL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GHS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GHS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GIP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GIP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GMD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GNF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GNF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GTQ(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GTQ());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GYD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GYD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HKD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HKD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HNL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HNL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HRK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HRK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HTG(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HTG());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HUF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HUF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IDR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IDR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ILS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ILS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_INR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().INR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IQD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IQD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IRR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().IRR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ISK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ISK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JMD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().JMD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JOD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().JOD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JPY(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().JPY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KES(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KES());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KGS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KGS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KHR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KHR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KMF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KMF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KPW(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KPW());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KRW(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KRW());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KWD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KWD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KYD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KYD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KZT(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().KZT());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LAK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LAK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LBP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LBP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LKR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LKR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LRD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LRD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LSL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LSL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LTL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LTL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LVL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LVL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LYD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LYD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MAD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MAD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MDL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MDL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MGA(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MGA());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MKD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MKD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MMK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MMK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MNT(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MNT());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MOP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MOP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MRO(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MRO());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MUR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MUR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MVR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MVR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MWK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MWK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MXN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MXN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MYR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MYR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MZN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MZN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NAD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NAD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NGN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NGN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NIO(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NIO());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NOK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NOK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NPR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NPR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NZD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NZD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OMR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().OMR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PAB(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PAB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PEN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PEN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PGK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PGK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PHP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PHP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PKR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PKR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PLN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PLN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PYG(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PYG());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QAR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().QAR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RON(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RON());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RSD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RSD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RUB(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RUB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RWF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RWF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SAR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SAR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SBD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SBD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SCR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SCR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SDG(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SDG());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SEK(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SEK());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SGD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SGD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SHP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SHP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SLL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SLL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SOS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SOS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SRD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SRD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_STD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().STD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SYP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SYP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SZL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SZL());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_THB(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().THB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TJS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TJS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TMT(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TMT());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TND(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TND());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TOP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TOP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TRY(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TRY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TTD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TTD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TWD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TWD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TZS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TZS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UAH(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UAH());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UGX(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UGX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_USD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().USD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UYU(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UYU());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UZS(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UZS());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VEF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VEF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VND(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VND());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VUV(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VUV());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WST(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WST());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XAF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XAF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XCD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XCD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XOF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XOF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XPF(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XPF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XXX(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XXX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YER(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().YER());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZAR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZAR());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZMW(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZMW());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZWL(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZWL());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICurrencyIdentifiersStatics2> : produce_base<D, winrt::Windows::Globalization::ICurrencyIdentifiersStatics2>
    {
        int32_t __stdcall get_BYN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().BYN());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ICurrencyIdentifiersStatics3> : produce_base<D, winrt::Windows::Globalization::ICurrencyIdentifiersStatics3>
    {
        int32_t __stdcall get_MRU(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MRU());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SSP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SSP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_STN(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().STN());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VES(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VES());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IGeographicRegion> : produce_base<D, winrt::Windows::Globalization::IGeographicRegion>
    {
        int32_t __stdcall get_Code(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CodeTwoLetter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CodeTwoLetter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CodeThreeLetter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CodeThreeLetter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CodeThreeDigit(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CodeThreeDigit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NativeName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NativeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrenciesInUse(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().CurrenciesInUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IGeographicRegionFactory> : produce_base<D, winrt::Windows::Globalization::IGeographicRegionFactory>
    {
        int32_t __stdcall CreateGeographicRegion(void* geographicRegionCode, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::GeographicRegion>(this->shim().CreateGeographicRegion(*reinterpret_cast<hstring const*>(&geographicRegionCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IGeographicRegionStatics> : produce_base<D, winrt::Windows::Globalization::IGeographicRegionStatics>
    {
        int32_t __stdcall IsSupported(void* geographicRegionCode, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSupported(*reinterpret_cast<hstring const*>(&geographicRegionCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IJapanesePhoneme> : produce_base<D, winrt::Windows::Globalization::IJapanesePhoneme>
    {
        int32_t __stdcall get_DisplayText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_YomiText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().YomiText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPhraseStart(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPhraseStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::IJapanesePhoneticAnalyzerStatics> : produce_base<D, winrt::Windows::Globalization::IJapanesePhoneticAnalyzerStatics>
    {
        int32_t __stdcall GetWords(void* input, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::JapanesePhoneme>>(this->shim().GetWords(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetWordsWithMonoRubyOption(void* input, bool monoRuby, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::JapanesePhoneme>>(this->shim().GetWords(*reinterpret_cast<hstring const*>(&input), monoRuby));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguage> : produce_base<D, winrt::Windows::Globalization::ILanguage>
    {
        int32_t __stdcall get_LanguageTag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LanguageTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NativeName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NativeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Script(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Script());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguage2> : produce_base<D, winrt::Windows::Globalization::ILanguage2>
    {
        int32_t __stdcall get_LayoutDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::LanguageLayoutDirection>(this->shim().LayoutDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguage3> : produce_base<D, winrt::Windows::Globalization::ILanguage3>
    {
        int32_t __stdcall get_AbbreviatedName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AbbreviatedName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguageExtensionSubtags> : produce_base<D, winrt::Windows::Globalization::ILanguageExtensionSubtags>
    {
        int32_t __stdcall GetExtensionSubtags(void* singleton, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetExtensionSubtags(*reinterpret_cast<hstring const*>(&singleton)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguageFactory> : produce_base<D, winrt::Windows::Globalization::ILanguageFactory>
    {
        int32_t __stdcall CreateLanguage(void* languageTag, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::Language>(this->shim().CreateLanguage(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguageStatics> : produce_base<D, winrt::Windows::Globalization::ILanguageStatics>
    {
        int32_t __stdcall IsWellFormed(void* languageTag, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsWellFormed(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentInputMethodLanguageTag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().CurrentInputMethodLanguageTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguageStatics2> : produce_base<D, winrt::Windows::Globalization::ILanguageStatics2>
    {
        int32_t __stdcall TrySetInputMethodLanguageTag(void* languageTag, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().TrySetInputMethodLanguageTag(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ILanguageStatics3> : produce_base<D, winrt::Windows::Globalization::ILanguageStatics3>
    {
        int32_t __stdcall GetMuiCompatibleLanguageListFromLanguageTags(void* languageTags, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetMuiCompatibleLanguageListFromLanguageTags(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languageTags)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::INumeralSystemIdentifiersStatics> : produce_base<D, winrt::Windows::Globalization::INumeralSystemIdentifiersStatics>
    {
        int32_t __stdcall get_Arab(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Arab());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ArabExt(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ArabExt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bali(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Bali());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Beng(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Beng());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Cham(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Cham());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Deva(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Deva());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FullWide(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FullWide());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gujr(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Gujr());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Guru(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Guru());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HaniDec(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HaniDec());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Java(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Java());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Kali(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Kali());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Khmr(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Khmr());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Knda(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Knda());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Lana(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Lana());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LanaTham(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LanaTham());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Laoo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Laoo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Latn(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Latn());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Lepc(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Lepc());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Limb(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Limb());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mlym(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mlym());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mong(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mong());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mtei(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mtei());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mymr(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mymr());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MymrShan(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MymrShan());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Nkoo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Nkoo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Olck(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Olck());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orya(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Orya());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Saur(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Saur());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Sund(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Sund());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Talu(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Talu());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TamlDec(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TamlDec());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Telu(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Telu());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thai(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Thai());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tibt(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tibt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Vaii(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Vaii());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2> : produce_base<D, winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2>
    {
        int32_t __stdcall get_Brah(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Brah());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Osma(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Osma());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MathBold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MathBold());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MathDbl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MathDbl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MathSans(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MathSans());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MathSanb(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MathSanb());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MathMono(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MathMono());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZmthBold(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZmthBold());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZmthDbl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZmthDbl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZmthSans(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZmthSans());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZmthSanb(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZmthSanb());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZmthMono(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ZmthMono());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::ITimeZoneOnCalendar> : produce_base<D, winrt::Windows::Globalization::ITimeZoneOnCalendar>
    {
        int32_t __stdcall GetTimeZone(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetTimeZone());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ChangeTimeZone(void* timeZoneId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChangeTimeZone(*reinterpret_cast<hstring const*>(&timeZoneId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TimeZoneAsFullString(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().TimeZoneAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TimeZoneAsString(int32_t idealLength, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().TimeZoneAsString(idealLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Globalization
{
    inline auto ApplicationLanguages::PrimaryLanguageOverride()
    {
        return impl::call_factory_cast<hstring(*)(IApplicationLanguagesStatics const&), ApplicationLanguages, IApplicationLanguagesStatics>([](IApplicationLanguagesStatics const& f) { return f.PrimaryLanguageOverride(); });
    }
    inline auto ApplicationLanguages::PrimaryLanguageOverride(param::hstring const& value)
    {
        impl::call_factory<ApplicationLanguages, IApplicationLanguagesStatics>([&](IApplicationLanguagesStatics const& f) { return f.PrimaryLanguageOverride(value); });
    }
    inline auto ApplicationLanguages::Languages()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring>(*)(IApplicationLanguagesStatics const&), ApplicationLanguages, IApplicationLanguagesStatics>([](IApplicationLanguagesStatics const& f) { return f.Languages(); });
    }
    inline auto ApplicationLanguages::ManifestLanguages()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring>(*)(IApplicationLanguagesStatics const&), ApplicationLanguages, IApplicationLanguagesStatics>([](IApplicationLanguagesStatics const& f) { return f.ManifestLanguages(); });
    }
    inline auto ApplicationLanguages::GetLanguagesForUser(winrt::Windows::System::User const& user)
    {
        return impl::call_factory<ApplicationLanguages, IApplicationLanguagesStatics2>([&](IApplicationLanguagesStatics2 const& f) { return f.GetLanguagesForUser(user); });
    }
    inline Calendar::Calendar() :
        Calendar(impl::call_factory_cast<Calendar(*)(winrt::Windows::Foundation::IActivationFactory const&), Calendar>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<Calendar>(); }))
    {
    }
    inline Calendar::Calendar(param::iterable<hstring> const& languages) :
        Calendar(impl::call_factory<Calendar, ICalendarFactory>([&](ICalendarFactory const& f) { return f.CreateCalendarDefaultCalendarAndClock(languages); }))
    {
    }
    inline Calendar::Calendar(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock) :
        Calendar(impl::call_factory<Calendar, ICalendarFactory>([&](ICalendarFactory const& f) { return f.CreateCalendar(languages, calendar, clock); }))
    {
    }
    inline Calendar::Calendar(param::iterable<hstring> const& languages, param::hstring const& calendar, param::hstring const& clock, param::hstring const& timeZoneId) :
        Calendar(impl::call_factory<Calendar, ICalendarFactory2>([&](ICalendarFactory2 const& f) { return f.CreateCalendarWithTimeZone(languages, calendar, clock, timeZoneId); }))
    {
    }
    inline auto CalendarIdentifiers::Gregorian()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Gregorian(); });
    }
    inline auto CalendarIdentifiers::Hebrew()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Hebrew(); });
    }
    inline auto CalendarIdentifiers::Hijri()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Hijri(); });
    }
    inline auto CalendarIdentifiers::Japanese()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Japanese(); });
    }
    inline auto CalendarIdentifiers::Julian()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Julian(); });
    }
    inline auto CalendarIdentifiers::Korean()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Korean(); });
    }
    inline auto CalendarIdentifiers::Taiwan()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Taiwan(); });
    }
    inline auto CalendarIdentifiers::Thai()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.Thai(); });
    }
    inline auto CalendarIdentifiers::UmAlQura()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics const&), CalendarIdentifiers, ICalendarIdentifiersStatics>([](ICalendarIdentifiersStatics const& f) { return f.UmAlQura(); });
    }
    inline auto CalendarIdentifiers::Persian()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics2 const&), CalendarIdentifiers, ICalendarIdentifiersStatics2>([](ICalendarIdentifiersStatics2 const& f) { return f.Persian(); });
    }
    inline auto CalendarIdentifiers::ChineseLunar()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics3 const&), CalendarIdentifiers, ICalendarIdentifiersStatics3>([](ICalendarIdentifiersStatics3 const& f) { return f.ChineseLunar(); });
    }
    inline auto CalendarIdentifiers::JapaneseLunar()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics3 const&), CalendarIdentifiers, ICalendarIdentifiersStatics3>([](ICalendarIdentifiersStatics3 const& f) { return f.JapaneseLunar(); });
    }
    inline auto CalendarIdentifiers::KoreanLunar()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics3 const&), CalendarIdentifiers, ICalendarIdentifiersStatics3>([](ICalendarIdentifiersStatics3 const& f) { return f.KoreanLunar(); });
    }
    inline auto CalendarIdentifiers::TaiwanLunar()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics3 const&), CalendarIdentifiers, ICalendarIdentifiersStatics3>([](ICalendarIdentifiersStatics3 const& f) { return f.TaiwanLunar(); });
    }
    inline auto CalendarIdentifiers::VietnameseLunar()
    {
        return impl::call_factory_cast<hstring(*)(ICalendarIdentifiersStatics3 const&), CalendarIdentifiers, ICalendarIdentifiersStatics3>([](ICalendarIdentifiersStatics3 const& f) { return f.VietnameseLunar(); });
    }
    inline auto ClockIdentifiers::TwelveHour()
    {
        return impl::call_factory_cast<hstring(*)(IClockIdentifiersStatics const&), ClockIdentifiers, IClockIdentifiersStatics>([](IClockIdentifiersStatics const& f) { return f.TwelveHour(); });
    }
    inline auto ClockIdentifiers::TwentyFourHour()
    {
        return impl::call_factory_cast<hstring(*)(IClockIdentifiersStatics const&), ClockIdentifiers, IClockIdentifiersStatics>([](IClockIdentifiersStatics const& f) { return f.TwentyFourHour(); });
    }
    inline CurrencyAmount::CurrencyAmount(param::hstring const& amount, param::hstring const& currency) :
        CurrencyAmount(impl::call_factory<CurrencyAmount, ICurrencyAmountFactory>([&](ICurrencyAmountFactory const& f) { return f.Create(amount, currency); }))
    {
    }
    inline auto CurrencyIdentifiers::AED()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.AED(); });
    }
    inline auto CurrencyIdentifiers::AFN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.AFN(); });
    }
    inline auto CurrencyIdentifiers::ALL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ALL(); });
    }
    inline auto CurrencyIdentifiers::AMD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.AMD(); });
    }
    inline auto CurrencyIdentifiers::ANG()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ANG(); });
    }
    inline auto CurrencyIdentifiers::AOA()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.AOA(); });
    }
    inline auto CurrencyIdentifiers::ARS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ARS(); });
    }
    inline auto CurrencyIdentifiers::AUD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.AUD(); });
    }
    inline auto CurrencyIdentifiers::AWG()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.AWG(); });
    }
    inline auto CurrencyIdentifiers::AZN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.AZN(); });
    }
    inline auto CurrencyIdentifiers::BAM()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BAM(); });
    }
    inline auto CurrencyIdentifiers::BBD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BBD(); });
    }
    inline auto CurrencyIdentifiers::BDT()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BDT(); });
    }
    inline auto CurrencyIdentifiers::BGN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BGN(); });
    }
    inline auto CurrencyIdentifiers::BHD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BHD(); });
    }
    inline auto CurrencyIdentifiers::BIF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BIF(); });
    }
    inline auto CurrencyIdentifiers::BMD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BMD(); });
    }
    inline auto CurrencyIdentifiers::BND()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BND(); });
    }
    inline auto CurrencyIdentifiers::BOB()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BOB(); });
    }
    inline auto CurrencyIdentifiers::BRL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BRL(); });
    }
    inline auto CurrencyIdentifiers::BSD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BSD(); });
    }
    inline auto CurrencyIdentifiers::BTN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BTN(); });
    }
    inline auto CurrencyIdentifiers::BWP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BWP(); });
    }
    inline auto CurrencyIdentifiers::BYR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BYR(); });
    }
    inline auto CurrencyIdentifiers::BZD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.BZD(); });
    }
    inline auto CurrencyIdentifiers::CAD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CAD(); });
    }
    inline auto CurrencyIdentifiers::CDF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CDF(); });
    }
    inline auto CurrencyIdentifiers::CHF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CHF(); });
    }
    inline auto CurrencyIdentifiers::CLP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CLP(); });
    }
    inline auto CurrencyIdentifiers::CNY()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CNY(); });
    }
    inline auto CurrencyIdentifiers::COP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.COP(); });
    }
    inline auto CurrencyIdentifiers::CRC()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CRC(); });
    }
    inline auto CurrencyIdentifiers::CUP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CUP(); });
    }
    inline auto CurrencyIdentifiers::CVE()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CVE(); });
    }
    inline auto CurrencyIdentifiers::CZK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.CZK(); });
    }
    inline auto CurrencyIdentifiers::DJF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.DJF(); });
    }
    inline auto CurrencyIdentifiers::DKK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.DKK(); });
    }
    inline auto CurrencyIdentifiers::DOP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.DOP(); });
    }
    inline auto CurrencyIdentifiers::DZD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.DZD(); });
    }
    inline auto CurrencyIdentifiers::EGP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.EGP(); });
    }
    inline auto CurrencyIdentifiers::ERN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ERN(); });
    }
    inline auto CurrencyIdentifiers::ETB()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ETB(); });
    }
    inline auto CurrencyIdentifiers::EUR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.EUR(); });
    }
    inline auto CurrencyIdentifiers::FJD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.FJD(); });
    }
    inline auto CurrencyIdentifiers::FKP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.FKP(); });
    }
    inline auto CurrencyIdentifiers::GBP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GBP(); });
    }
    inline auto CurrencyIdentifiers::GEL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GEL(); });
    }
    inline auto CurrencyIdentifiers::GHS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GHS(); });
    }
    inline auto CurrencyIdentifiers::GIP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GIP(); });
    }
    inline auto CurrencyIdentifiers::GMD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GMD(); });
    }
    inline auto CurrencyIdentifiers::GNF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GNF(); });
    }
    inline auto CurrencyIdentifiers::GTQ()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GTQ(); });
    }
    inline auto CurrencyIdentifiers::GYD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.GYD(); });
    }
    inline auto CurrencyIdentifiers::HKD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.HKD(); });
    }
    inline auto CurrencyIdentifiers::HNL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.HNL(); });
    }
    inline auto CurrencyIdentifiers::HRK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.HRK(); });
    }
    inline auto CurrencyIdentifiers::HTG()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.HTG(); });
    }
    inline auto CurrencyIdentifiers::HUF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.HUF(); });
    }
    inline auto CurrencyIdentifiers::IDR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.IDR(); });
    }
    inline auto CurrencyIdentifiers::ILS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ILS(); });
    }
    inline auto CurrencyIdentifiers::INR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.INR(); });
    }
    inline auto CurrencyIdentifiers::IQD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.IQD(); });
    }
    inline auto CurrencyIdentifiers::IRR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.IRR(); });
    }
    inline auto CurrencyIdentifiers::ISK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ISK(); });
    }
    inline auto CurrencyIdentifiers::JMD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.JMD(); });
    }
    inline auto CurrencyIdentifiers::JOD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.JOD(); });
    }
    inline auto CurrencyIdentifiers::JPY()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.JPY(); });
    }
    inline auto CurrencyIdentifiers::KES()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KES(); });
    }
    inline auto CurrencyIdentifiers::KGS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KGS(); });
    }
    inline auto CurrencyIdentifiers::KHR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KHR(); });
    }
    inline auto CurrencyIdentifiers::KMF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KMF(); });
    }
    inline auto CurrencyIdentifiers::KPW()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KPW(); });
    }
    inline auto CurrencyIdentifiers::KRW()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KRW(); });
    }
    inline auto CurrencyIdentifiers::KWD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KWD(); });
    }
    inline auto CurrencyIdentifiers::KYD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KYD(); });
    }
    inline auto CurrencyIdentifiers::KZT()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.KZT(); });
    }
    inline auto CurrencyIdentifiers::LAK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LAK(); });
    }
    inline auto CurrencyIdentifiers::LBP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LBP(); });
    }
    inline auto CurrencyIdentifiers::LKR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LKR(); });
    }
    inline auto CurrencyIdentifiers::LRD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LRD(); });
    }
    inline auto CurrencyIdentifiers::LSL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LSL(); });
    }
    inline auto CurrencyIdentifiers::LTL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LTL(); });
    }
    inline auto CurrencyIdentifiers::LVL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LVL(); });
    }
    inline auto CurrencyIdentifiers::LYD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.LYD(); });
    }
    inline auto CurrencyIdentifiers::MAD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MAD(); });
    }
    inline auto CurrencyIdentifiers::MDL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MDL(); });
    }
    inline auto CurrencyIdentifiers::MGA()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MGA(); });
    }
    inline auto CurrencyIdentifiers::MKD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MKD(); });
    }
    inline auto CurrencyIdentifiers::MMK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MMK(); });
    }
    inline auto CurrencyIdentifiers::MNT()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MNT(); });
    }
    inline auto CurrencyIdentifiers::MOP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MOP(); });
    }
    inline auto CurrencyIdentifiers::MRO()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MRO(); });
    }
    inline auto CurrencyIdentifiers::MUR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MUR(); });
    }
    inline auto CurrencyIdentifiers::MVR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MVR(); });
    }
    inline auto CurrencyIdentifiers::MWK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MWK(); });
    }
    inline auto CurrencyIdentifiers::MXN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MXN(); });
    }
    inline auto CurrencyIdentifiers::MYR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MYR(); });
    }
    inline auto CurrencyIdentifiers::MZN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.MZN(); });
    }
    inline auto CurrencyIdentifiers::NAD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.NAD(); });
    }
    inline auto CurrencyIdentifiers::NGN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.NGN(); });
    }
    inline auto CurrencyIdentifiers::NIO()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.NIO(); });
    }
    inline auto CurrencyIdentifiers::NOK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.NOK(); });
    }
    inline auto CurrencyIdentifiers::NPR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.NPR(); });
    }
    inline auto CurrencyIdentifiers::NZD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.NZD(); });
    }
    inline auto CurrencyIdentifiers::OMR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.OMR(); });
    }
    inline auto CurrencyIdentifiers::PAB()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.PAB(); });
    }
    inline auto CurrencyIdentifiers::PEN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.PEN(); });
    }
    inline auto CurrencyIdentifiers::PGK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.PGK(); });
    }
    inline auto CurrencyIdentifiers::PHP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.PHP(); });
    }
    inline auto CurrencyIdentifiers::PKR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.PKR(); });
    }
    inline auto CurrencyIdentifiers::PLN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.PLN(); });
    }
    inline auto CurrencyIdentifiers::PYG()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.PYG(); });
    }
    inline auto CurrencyIdentifiers::QAR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.QAR(); });
    }
    inline auto CurrencyIdentifiers::RON()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.RON(); });
    }
    inline auto CurrencyIdentifiers::RSD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.RSD(); });
    }
    inline auto CurrencyIdentifiers::RUB()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.RUB(); });
    }
    inline auto CurrencyIdentifiers::RWF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.RWF(); });
    }
    inline auto CurrencyIdentifiers::SAR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SAR(); });
    }
    inline auto CurrencyIdentifiers::SBD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SBD(); });
    }
    inline auto CurrencyIdentifiers::SCR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SCR(); });
    }
    inline auto CurrencyIdentifiers::SDG()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SDG(); });
    }
    inline auto CurrencyIdentifiers::SEK()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SEK(); });
    }
    inline auto CurrencyIdentifiers::SGD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SGD(); });
    }
    inline auto CurrencyIdentifiers::SHP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SHP(); });
    }
    inline auto CurrencyIdentifiers::SLL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SLL(); });
    }
    inline auto CurrencyIdentifiers::SOS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SOS(); });
    }
    inline auto CurrencyIdentifiers::SRD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SRD(); });
    }
    inline auto CurrencyIdentifiers::STD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.STD(); });
    }
    inline auto CurrencyIdentifiers::SYP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SYP(); });
    }
    inline auto CurrencyIdentifiers::SZL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.SZL(); });
    }
    inline auto CurrencyIdentifiers::THB()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.THB(); });
    }
    inline auto CurrencyIdentifiers::TJS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TJS(); });
    }
    inline auto CurrencyIdentifiers::TMT()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TMT(); });
    }
    inline auto CurrencyIdentifiers::TND()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TND(); });
    }
    inline auto CurrencyIdentifiers::TOP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TOP(); });
    }
    inline auto CurrencyIdentifiers::TRY()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TRY(); });
    }
    inline auto CurrencyIdentifiers::TTD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TTD(); });
    }
    inline auto CurrencyIdentifiers::TWD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TWD(); });
    }
    inline auto CurrencyIdentifiers::TZS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.TZS(); });
    }
    inline auto CurrencyIdentifiers::UAH()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.UAH(); });
    }
    inline auto CurrencyIdentifiers::UGX()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.UGX(); });
    }
    inline auto CurrencyIdentifiers::USD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.USD(); });
    }
    inline auto CurrencyIdentifiers::UYU()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.UYU(); });
    }
    inline auto CurrencyIdentifiers::UZS()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.UZS(); });
    }
    inline auto CurrencyIdentifiers::VEF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.VEF(); });
    }
    inline auto CurrencyIdentifiers::VND()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.VND(); });
    }
    inline auto CurrencyIdentifiers::VUV()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.VUV(); });
    }
    inline auto CurrencyIdentifiers::WST()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.WST(); });
    }
    inline auto CurrencyIdentifiers::XAF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.XAF(); });
    }
    inline auto CurrencyIdentifiers::XCD()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.XCD(); });
    }
    inline auto CurrencyIdentifiers::XOF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.XOF(); });
    }
    inline auto CurrencyIdentifiers::XPF()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.XPF(); });
    }
    inline auto CurrencyIdentifiers::XXX()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.XXX(); });
    }
    inline auto CurrencyIdentifiers::YER()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.YER(); });
    }
    inline auto CurrencyIdentifiers::ZAR()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ZAR(); });
    }
    inline auto CurrencyIdentifiers::ZMW()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ZMW(); });
    }
    inline auto CurrencyIdentifiers::ZWL()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics>([](ICurrencyIdentifiersStatics const& f) { return f.ZWL(); });
    }
    inline auto CurrencyIdentifiers::BYN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics2 const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics2>([](ICurrencyIdentifiersStatics2 const& f) { return f.BYN(); });
    }
    inline auto CurrencyIdentifiers::MRU()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics3 const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics3>([](ICurrencyIdentifiersStatics3 const& f) { return f.MRU(); });
    }
    inline auto CurrencyIdentifiers::SSP()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics3 const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics3>([](ICurrencyIdentifiersStatics3 const& f) { return f.SSP(); });
    }
    inline auto CurrencyIdentifiers::STN()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics3 const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics3>([](ICurrencyIdentifiersStatics3 const& f) { return f.STN(); });
    }
    inline auto CurrencyIdentifiers::VES()
    {
        return impl::call_factory_cast<hstring(*)(ICurrencyIdentifiersStatics3 const&), CurrencyIdentifiers, ICurrencyIdentifiersStatics3>([](ICurrencyIdentifiersStatics3 const& f) { return f.VES(); });
    }
    inline GeographicRegion::GeographicRegion() :
        GeographicRegion(impl::call_factory_cast<GeographicRegion(*)(winrt::Windows::Foundation::IActivationFactory const&), GeographicRegion>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<GeographicRegion>(); }))
    {
    }
    inline GeographicRegion::GeographicRegion(param::hstring const& geographicRegionCode) :
        GeographicRegion(impl::call_factory<GeographicRegion, IGeographicRegionFactory>([&](IGeographicRegionFactory const& f) { return f.CreateGeographicRegion(geographicRegionCode); }))
    {
    }
    inline auto GeographicRegion::IsSupported(param::hstring const& geographicRegionCode)
    {
        return impl::call_factory<GeographicRegion, IGeographicRegionStatics>([&](IGeographicRegionStatics const& f) { return f.IsSupported(geographicRegionCode); });
    }
    inline auto JapanesePhoneticAnalyzer::GetWords(param::hstring const& input)
    {
        return impl::call_factory<JapanesePhoneticAnalyzer, IJapanesePhoneticAnalyzerStatics>([&](IJapanesePhoneticAnalyzerStatics const& f) { return f.GetWords(input); });
    }
    inline auto JapanesePhoneticAnalyzer::GetWords(param::hstring const& input, bool monoRuby)
    {
        return impl::call_factory<JapanesePhoneticAnalyzer, IJapanesePhoneticAnalyzerStatics>([&](IJapanesePhoneticAnalyzerStatics const& f) { return f.GetWords(input, monoRuby); });
    }
    inline Language::Language(param::hstring const& languageTag) :
        Language(impl::call_factory<Language, ILanguageFactory>([&](ILanguageFactory const& f) { return f.CreateLanguage(languageTag); }))
    {
    }
    inline auto Language::IsWellFormed(param::hstring const& languageTag)
    {
        return impl::call_factory<Language, ILanguageStatics>([&](ILanguageStatics const& f) { return f.IsWellFormed(languageTag); });
    }
    inline auto Language::CurrentInputMethodLanguageTag()
    {
        return impl::call_factory_cast<hstring(*)(ILanguageStatics const&), Language, ILanguageStatics>([](ILanguageStatics const& f) { return f.CurrentInputMethodLanguageTag(); });
    }
    inline auto Language::TrySetInputMethodLanguageTag(param::hstring const& languageTag)
    {
        return impl::call_factory<Language, ILanguageStatics2>([&](ILanguageStatics2 const& f) { return f.TrySetInputMethodLanguageTag(languageTag); });
    }
    inline auto Language::GetMuiCompatibleLanguageListFromLanguageTags(param::iterable<hstring> const& languageTags)
    {
        return impl::call_factory<Language, ILanguageStatics3>([&](ILanguageStatics3 const& f) { return f.GetMuiCompatibleLanguageListFromLanguageTags(languageTags); });
    }
    inline auto NumeralSystemIdentifiers::Arab()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Arab(); });
    }
    inline auto NumeralSystemIdentifiers::ArabExt()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.ArabExt(); });
    }
    inline auto NumeralSystemIdentifiers::Bali()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Bali(); });
    }
    inline auto NumeralSystemIdentifiers::Beng()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Beng(); });
    }
    inline auto NumeralSystemIdentifiers::Cham()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Cham(); });
    }
    inline auto NumeralSystemIdentifiers::Deva()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Deva(); });
    }
    inline auto NumeralSystemIdentifiers::FullWide()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.FullWide(); });
    }
    inline auto NumeralSystemIdentifiers::Gujr()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Gujr(); });
    }
    inline auto NumeralSystemIdentifiers::Guru()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Guru(); });
    }
    inline auto NumeralSystemIdentifiers::HaniDec()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.HaniDec(); });
    }
    inline auto NumeralSystemIdentifiers::Java()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Java(); });
    }
    inline auto NumeralSystemIdentifiers::Kali()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Kali(); });
    }
    inline auto NumeralSystemIdentifiers::Khmr()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Khmr(); });
    }
    inline auto NumeralSystemIdentifiers::Knda()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Knda(); });
    }
    inline auto NumeralSystemIdentifiers::Lana()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Lana(); });
    }
    inline auto NumeralSystemIdentifiers::LanaTham()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.LanaTham(); });
    }
    inline auto NumeralSystemIdentifiers::Laoo()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Laoo(); });
    }
    inline auto NumeralSystemIdentifiers::Latn()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Latn(); });
    }
    inline auto NumeralSystemIdentifiers::Lepc()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Lepc(); });
    }
    inline auto NumeralSystemIdentifiers::Limb()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Limb(); });
    }
    inline auto NumeralSystemIdentifiers::Mlym()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Mlym(); });
    }
    inline auto NumeralSystemIdentifiers::Mong()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Mong(); });
    }
    inline auto NumeralSystemIdentifiers::Mtei()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Mtei(); });
    }
    inline auto NumeralSystemIdentifiers::Mymr()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Mymr(); });
    }
    inline auto NumeralSystemIdentifiers::MymrShan()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.MymrShan(); });
    }
    inline auto NumeralSystemIdentifiers::Nkoo()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Nkoo(); });
    }
    inline auto NumeralSystemIdentifiers::Olck()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Olck(); });
    }
    inline auto NumeralSystemIdentifiers::Orya()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Orya(); });
    }
    inline auto NumeralSystemIdentifiers::Saur()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Saur(); });
    }
    inline auto NumeralSystemIdentifiers::Sund()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Sund(); });
    }
    inline auto NumeralSystemIdentifiers::Talu()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Talu(); });
    }
    inline auto NumeralSystemIdentifiers::TamlDec()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.TamlDec(); });
    }
    inline auto NumeralSystemIdentifiers::Telu()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Telu(); });
    }
    inline auto NumeralSystemIdentifiers::Thai()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Thai(); });
    }
    inline auto NumeralSystemIdentifiers::Tibt()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Tibt(); });
    }
    inline auto NumeralSystemIdentifiers::Vaii()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics>([](INumeralSystemIdentifiersStatics const& f) { return f.Vaii(); });
    }
    inline auto NumeralSystemIdentifiers::Brah()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.Brah(); });
    }
    inline auto NumeralSystemIdentifiers::Osma()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.Osma(); });
    }
    inline auto NumeralSystemIdentifiers::MathBold()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.MathBold(); });
    }
    inline auto NumeralSystemIdentifiers::MathDbl()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.MathDbl(); });
    }
    inline auto NumeralSystemIdentifiers::MathSans()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.MathSans(); });
    }
    inline auto NumeralSystemIdentifiers::MathSanb()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.MathSanb(); });
    }
    inline auto NumeralSystemIdentifiers::MathMono()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.MathMono(); });
    }
    inline auto NumeralSystemIdentifiers::ZmthBold()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.ZmthBold(); });
    }
    inline auto NumeralSystemIdentifiers::ZmthDbl()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.ZmthDbl(); });
    }
    inline auto NumeralSystemIdentifiers::ZmthSans()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.ZmthSans(); });
    }
    inline auto NumeralSystemIdentifiers::ZmthSanb()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.ZmthSanb(); });
    }
    inline auto NumeralSystemIdentifiers::ZmthMono()
    {
        return impl::call_factory_cast<hstring(*)(INumeralSystemIdentifiersStatics2 const&), NumeralSystemIdentifiers, INumeralSystemIdentifiersStatics2>([](INumeralSystemIdentifiersStatics2 const& f) { return f.ZmthMono(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Globalization::IApplicationLanguagesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::IApplicationLanguagesStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICalendar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICalendarFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICalendarFactory2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICalendarIdentifiersStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICalendarIdentifiersStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICalendarIdentifiersStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::IClockIdentifiersStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICurrencyAmount> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICurrencyAmountFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICurrencyIdentifiersStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICurrencyIdentifiersStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ICurrencyIdentifiersStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::IGeographicRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::IGeographicRegionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::IGeographicRegionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::IJapanesePhoneme> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::IJapanesePhoneticAnalyzerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguage2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguage3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguageExtensionSubtags> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguageStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguageStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ILanguageStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::INumeralSystemIdentifiersStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::INumeralSystemIdentifiersStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ITimeZoneOnCalendar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ApplicationLanguages> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Calendar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::CalendarIdentifiers> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::ClockIdentifiers> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::CurrencyAmount> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::CurrencyIdentifiers> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::GeographicRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::JapanesePhoneme> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::JapanesePhoneticAnalyzer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::Language> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::NumeralSystemIdentifiers> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
