// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Globalization_DateTimeFormatting_H
#define WINRT_Windows_Globalization_DateTimeFormatting_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Globalization.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Globalization.DateTimeFormatting.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Languages() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Languages(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::GeographicRegion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_GeographicRegion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Calendar() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Calendar(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Clock() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Clock(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::NumeralSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_NumeralSystem(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::NumeralSystem(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->put_NumeralSystem(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Patterns() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Patterns(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Template() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_Template(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::Format(winrt::Windows::Foundation::DateTime const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->Format(impl::bind_in(value), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::YearFormat) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeYear() const
    {
        winrt::Windows::Globalization::DateTimeFormatting::YearFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeYear(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::MonthFormat) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeMonth() const
    {
        winrt::Windows::Globalization::DateTimeFormatting::MonthFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeMonth(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeDayOfWeek() const
    {
        winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeDayOfWeek(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DayFormat) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeDay() const
    {
        winrt::Windows::Globalization::DateTimeFormatting::DayFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeDay(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::HourFormat) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeHour() const
    {
        winrt::Windows::Globalization::DateTimeFormatting::HourFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeHour(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeMinute() const
    {
        winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeMinute(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::SecondFormat) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::IncludeSecond() const
    {
        winrt::Windows::Globalization::DateTimeFormatting::SecondFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_IncludeSecond(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::ResolvedLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_ResolvedLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter<D>::ResolvedGeographicRegion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter)->get_ResolvedGeographicRegion(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatter2<D>::Format(winrt::Windows::Foundation::DateTime const& datetime, param::hstring const& timeZoneId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2)->FormatUsingTimeZone(impl::bind_in(datetime), *(void**)(&timeZoneId), &result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatter(param::hstring const& formatTemplate) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatter(*(void**)(&formatTemplate), &result));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterLanguages(param::hstring const& formatTemplate, param::iterable<hstring> const& languages) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterLanguages(*(void**)(&formatTemplate), *(void**)(&languages), &result));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterContext(param::hstring const& formatTemplate, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterContext(*(void**)(&formatTemplate), *(void**)(&languages), *(void**)(&geographicRegion), *(void**)(&calendar), *(void**)(&clock), &result));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterDate(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterDate(static_cast<int32_t>(yearFormat), static_cast<int32_t>(monthFormat), static_cast<int32_t>(dayFormat), static_cast<int32_t>(dayOfWeekFormat), &result));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterTime(winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterTime(static_cast<int32_t>(hourFormat), static_cast<int32_t>(minuteFormat), static_cast<int32_t>(secondFormat), &result));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterDateTimeLanguages(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterDateTimeLanguages(static_cast<int32_t>(yearFormat), static_cast<int32_t>(monthFormat), static_cast<int32_t>(dayFormat), static_cast<int32_t>(dayOfWeekFormat), static_cast<int32_t>(hourFormat), static_cast<int32_t>(minuteFormat), static_cast<int32_t>(secondFormat), *(void**)(&languages), &result));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterFactory<D>::CreateDateTimeFormatterDateTimeContext(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory)->CreateDateTimeFormatterDateTimeContext(static_cast<int32_t>(yearFormat), static_cast<int32_t>(monthFormat), static_cast<int32_t>(dayFormat), static_cast<int32_t>(dayOfWeekFormat), static_cast<int32_t>(hourFormat), static_cast<int32_t>(minuteFormat), static_cast<int32_t>(secondFormat), *(void**)(&languages), *(void**)(&geographicRegion), *(void**)(&calendar), *(void**)(&clock), &result));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::LongDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_LongDate(&value));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::LongTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_LongTime(&value));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::ShortDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_ShortDate(&value));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter) consume_Windows_Globalization_DateTimeFormatting_IDateTimeFormatterStatics<D>::ShortTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics)->get_ShortTime(&value));
        return winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter> : produce_base<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter>
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
        int32_t __stdcall get_Calendar(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Calendar());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Clock(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Clock());
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
        int32_t __stdcall get_Patterns(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Patterns());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Template(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Template());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Format(int64_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Format(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeYear(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::YearFormat>(this->shim().IncludeYear());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeMonth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::MonthFormat>(this->shim().IncludeMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeDayOfWeek(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat>(this->shim().IncludeDayOfWeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeDay(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DayFormat>(this->shim().IncludeDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeHour(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::HourFormat>(this->shim().IncludeHour());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeMinute(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat>(this->shim().IncludeMinute());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeSecond(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::SecondFormat>(this->shim().IncludeSecond());
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
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2> : produce_base<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2>
    {
        int32_t __stdcall FormatUsingTimeZone(int64_t datetime, void* timeZoneId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().Format(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&datetime), *reinterpret_cast<hstring const*>(&timeZoneId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory> : produce_base<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory>
    {
        int32_t __stdcall CreateDateTimeFormatter(void* formatTemplate, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatter(*reinterpret_cast<hstring const*>(&formatTemplate)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTimeFormatterLanguages(void* formatTemplate, void* languages, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterLanguages(*reinterpret_cast<hstring const*>(&formatTemplate), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTimeFormatterContext(void* formatTemplate, void* languages, void* geographicRegion, void* calendar, void* clock, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterContext(*reinterpret_cast<hstring const*>(&formatTemplate), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTimeFormatterDate(int32_t yearFormat, int32_t monthFormat, int32_t dayFormat, int32_t dayOfWeekFormat, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterDate(*reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::YearFormat const*>(&yearFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const*>(&monthFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::DayFormat const*>(&dayFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const*>(&dayOfWeekFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTimeFormatterTime(int32_t hourFormat, int32_t minuteFormat, int32_t secondFormat, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterTime(*reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::HourFormat const*>(&hourFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const*>(&minuteFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const*>(&secondFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTimeFormatterDateTimeLanguages(int32_t yearFormat, int32_t monthFormat, int32_t dayFormat, int32_t dayOfWeekFormat, int32_t hourFormat, int32_t minuteFormat, int32_t secondFormat, void* languages, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterDateTimeLanguages(*reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::YearFormat const*>(&yearFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const*>(&monthFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::DayFormat const*>(&dayFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const*>(&dayOfWeekFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::HourFormat const*>(&hourFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const*>(&minuteFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const*>(&secondFormat), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTimeFormatterDateTimeContext(int32_t yearFormat, int32_t monthFormat, int32_t dayFormat, int32_t dayOfWeekFormat, int32_t hourFormat, int32_t minuteFormat, int32_t secondFormat, void* languages, void* geographicRegion, void* calendar, void* clock, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().CreateDateTimeFormatterDateTimeContext(*reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::YearFormat const*>(&yearFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const*>(&monthFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::DayFormat const*>(&dayFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const*>(&dayOfWeekFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::HourFormat const*>(&hourFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const*>(&minuteFormat), *reinterpret_cast<winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const*>(&secondFormat), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&languages), *reinterpret_cast<hstring const*>(&geographicRegion), *reinterpret_cast<hstring const*>(&calendar), *reinterpret_cast<hstring const*>(&clock)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics> : produce_base<D, winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics>
    {
        int32_t __stdcall get_LongDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().LongDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LongTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().LongTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShortDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().ShortDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShortTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter>(this->shim().ShortTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Globalization::DateTimeFormatting
{
    inline DateTimeFormatter::DateTimeFormatter(param::hstring const& formatTemplate) :
        DateTimeFormatter(impl::call_factory<DateTimeFormatter, IDateTimeFormatterFactory>([&](IDateTimeFormatterFactory const& f) { return f.CreateDateTimeFormatter(formatTemplate); }))
    {
    }
    inline DateTimeFormatter::DateTimeFormatter(param::hstring const& formatTemplate, param::iterable<hstring> const& languages) :
        DateTimeFormatter(impl::call_factory<DateTimeFormatter, IDateTimeFormatterFactory>([&](IDateTimeFormatterFactory const& f) { return f.CreateDateTimeFormatterLanguages(formatTemplate, languages); }))
    {
    }
    inline DateTimeFormatter::DateTimeFormatter(param::hstring const& formatTemplate, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) :
        DateTimeFormatter(impl::call_factory<DateTimeFormatter, IDateTimeFormatterFactory>([&](IDateTimeFormatterFactory const& f) { return f.CreateDateTimeFormatterContext(formatTemplate, languages, geographicRegion, calendar, clock); }))
    {
    }
    inline DateTimeFormatter::DateTimeFormatter(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat) :
        DateTimeFormatter(impl::call_factory<DateTimeFormatter, IDateTimeFormatterFactory>([&](IDateTimeFormatterFactory const& f) { return f.CreateDateTimeFormatterDate(yearFormat, monthFormat, dayFormat, dayOfWeekFormat); }))
    {
    }
    inline DateTimeFormatter::DateTimeFormatter(winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat) :
        DateTimeFormatter(impl::call_factory<DateTimeFormatter, IDateTimeFormatterFactory>([&](IDateTimeFormatterFactory const& f) { return f.CreateDateTimeFormatterTime(hourFormat, minuteFormat, secondFormat); }))
    {
    }
    inline DateTimeFormatter::DateTimeFormatter(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages) :
        DateTimeFormatter(impl::call_factory<DateTimeFormatter, IDateTimeFormatterFactory>([&](IDateTimeFormatterFactory const& f) { return f.CreateDateTimeFormatterDateTimeLanguages(yearFormat, monthFormat, dayFormat, dayOfWeekFormat, hourFormat, minuteFormat, secondFormat, languages); }))
    {
    }
    inline DateTimeFormatter::DateTimeFormatter(winrt::Windows::Globalization::DateTimeFormatting::YearFormat const& yearFormat, winrt::Windows::Globalization::DateTimeFormatting::MonthFormat const& monthFormat, winrt::Windows::Globalization::DateTimeFormatting::DayFormat const& dayFormat, winrt::Windows::Globalization::DateTimeFormatting::DayOfWeekFormat const& dayOfWeekFormat, winrt::Windows::Globalization::DateTimeFormatting::HourFormat const& hourFormat, winrt::Windows::Globalization::DateTimeFormatting::MinuteFormat const& minuteFormat, winrt::Windows::Globalization::DateTimeFormatting::SecondFormat const& secondFormat, param::iterable<hstring> const& languages, param::hstring const& geographicRegion, param::hstring const& calendar, param::hstring const& clock) :
        DateTimeFormatter(impl::call_factory<DateTimeFormatter, IDateTimeFormatterFactory>([&](IDateTimeFormatterFactory const& f) { return f.CreateDateTimeFormatterDateTimeContext(yearFormat, monthFormat, dayFormat, dayOfWeekFormat, hourFormat, minuteFormat, secondFormat, languages, geographicRegion, calendar, clock); }))
    {
    }
    inline auto DateTimeFormatter::LongDate()
    {
        return impl::call_factory_cast<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter(*)(IDateTimeFormatterStatics const&), DateTimeFormatter, IDateTimeFormatterStatics>([](IDateTimeFormatterStatics const& f) { return f.LongDate(); });
    }
    inline auto DateTimeFormatter::LongTime()
    {
        return impl::call_factory_cast<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter(*)(IDateTimeFormatterStatics const&), DateTimeFormatter, IDateTimeFormatterStatics>([](IDateTimeFormatterStatics const& f) { return f.LongTime(); });
    }
    inline auto DateTimeFormatter::ShortDate()
    {
        return impl::call_factory_cast<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter(*)(IDateTimeFormatterStatics const&), DateTimeFormatter, IDateTimeFormatterStatics>([](IDateTimeFormatterStatics const& f) { return f.ShortDate(); });
    }
    inline auto DateTimeFormatter::ShortTime()
    {
        return impl::call_factory_cast<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter(*)(IDateTimeFormatterStatics const&), DateTimeFormatter, IDateTimeFormatterStatics>([](IDateTimeFormatterStatics const& f) { return f.ShortTime(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::IDateTimeFormatterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Globalization::DateTimeFormatting::DateTimeFormatter> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
