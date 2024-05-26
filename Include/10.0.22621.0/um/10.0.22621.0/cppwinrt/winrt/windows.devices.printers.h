// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Printers_H
#define WINRT_Windows_Devices_Printers_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Printing.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Printers.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeErrorReason) consume_Windows_Devices_Printers_IIppAttributeError<D>::Reason() const
    {
        winrt::Windows::Devices::Printers::IppAttributeErrorReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeError)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Devices_Printers_IIppAttributeError<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeError)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Printers::IppAttributeValue>) consume_Windows_Devices_Printers_IIppAttributeError<D>::GetUnsupportedValues() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeError)->GetUnsupportedValues(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Printers::IppAttributeValue>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValueKind) consume_Windows_Devices_Printers_IIppAttributeValue<D>::Kind() const
    {
        winrt::Windows::Devices::Printers::IppAttributeValueKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<int32_t>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetIntegerArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetIntegerArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<int32_t>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<bool>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetBooleanArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetBooleanArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<int32_t>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetEnumArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetEnumArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<int32_t>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetOctetStringArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetOctetStringArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IBuffer>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::DateTime>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetDateTimeArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetDateTimeArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::DateTime>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppResolution>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetResolutionArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetResolutionArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppResolution>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppIntegerRange>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetRangeOfIntegerArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetRangeOfIntegerArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppIntegerRange>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetCollectionArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetCollectionArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppTextWithLanguage>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetTextWithLanguageArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetTextWithLanguageArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppTextWithLanguage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppTextWithLanguage>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetNameWithLanguageArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetNameWithLanguageArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppTextWithLanguage>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetTextWithoutLanguageArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetTextWithoutLanguageArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetNameWithoutLanguageArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetNameWithoutLanguageArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetKeywordArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetKeywordArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetUriArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetUriArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetUriSchemaArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetUriSchemaArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetCharsetArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetCharsetArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetNaturalLanguageArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetNaturalLanguageArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Devices_Printers_IIppAttributeValue<D>::GetMimeMediaTypeArray() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValue)->GetMimeMediaTypeArray(&result));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateUnsupported() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateUnsupported(&result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateUnknown() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateUnknown(&result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateNoValue() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateNoValue(&result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateInteger(int32_t value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateInteger(value, &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateIntegerArray(param::iterable<int32_t> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateIntegerArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateBoolean(bool value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateBoolean(value, &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateBooleanArray(param::iterable<bool> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateBooleanArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateEnum(int32_t value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateEnum(value, &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateEnumArray(param::iterable<int32_t> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateEnumArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateOctetString(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateOctetString(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateOctetStringArray(param::iterable<winrt::Windows::Storage::Streams::IBuffer> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateOctetStringArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateDateTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateDateTime(impl::bind_in(value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateDateTimeArray(param::iterable<winrt::Windows::Foundation::DateTime> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateDateTimeArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateResolution(winrt::Windows::Devices::Printers::IppResolution const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateResolution(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateResolutionArray(param::iterable<winrt::Windows::Devices::Printers::IppResolution> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateResolutionArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateRangeOfInteger(winrt::Windows::Devices::Printers::IppIntegerRange const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateRangeOfInteger(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateRangeOfIntegerArray(param::iterable<winrt::Windows::Devices::Printers::IppIntegerRange> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateRangeOfIntegerArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateCollection(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const& memberAttributes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateCollection(*(void**)(&memberAttributes), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateCollectionArray(param::iterable<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>>> const& memberAttributesArray) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateCollectionArray(*(void**)(&memberAttributesArray), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateTextWithLanguage(winrt::Windows::Devices::Printers::IppTextWithLanguage const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateTextWithLanguage(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateTextWithLanguageArray(param::iterable<winrt::Windows::Devices::Printers::IppTextWithLanguage> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateTextWithLanguageArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateNameWithLanguage(winrt::Windows::Devices::Printers::IppTextWithLanguage const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateNameWithLanguage(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateNameWithLanguageArray(param::iterable<winrt::Windows::Devices::Printers::IppTextWithLanguage> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateNameWithLanguageArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateTextWithoutLanguage(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateTextWithoutLanguage(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateTextWithoutLanguageArray(param::iterable<hstring> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateTextWithoutLanguageArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateNameWithoutLanguage(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateNameWithoutLanguage(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateNameWithoutLanguageArray(param::iterable<hstring> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateNameWithoutLanguageArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateKeyword(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateKeyword(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateKeywordArray(param::iterable<hstring> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateKeywordArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateUri(winrt::Windows::Foundation::Uri const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateUri(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateUriArray(param::iterable<winrt::Windows::Foundation::Uri> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateUriArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateUriSchema(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateUriSchema(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateUriSchemaArray(param::iterable<hstring> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateUriSchemaArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateCharset(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateCharset(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateCharsetArray(param::iterable<hstring> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateCharsetArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateNaturalLanguage(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateNaturalLanguage(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateNaturalLanguageArray(param::iterable<hstring> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateNaturalLanguageArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateMimeMedia(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateMimeMedia(*(void**)(&value), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppAttributeValue) consume_Windows_Devices_Printers_IIppAttributeValueStatics<D>::CreateMimeMediaArray(param::iterable<hstring> const& values) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppAttributeValueStatics)->CreateMimeMediaArray(*(void**)(&values), &result));
        return winrt::Windows::Devices::Printers::IppAttributeValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Printers_IIppIntegerRange<D>::Start() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppIntegerRange)->get_Start(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Printers_IIppIntegerRange<D>::End() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppIntegerRange)->get_End(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppIntegerRange) consume_Windows_Devices_Printers_IIppIntegerRangeFactory<D>::CreateInstance(int32_t start, int32_t end) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppIntegerRangeFactory)->CreateInstance(start, end, &value));
        return winrt::Windows::Devices::Printers::IppIntegerRange{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_IIppPrintDevice<D>::PrinterName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice)->get_PrinterName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Devices_Printers_IIppPrintDevice<D>::PrinterUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice)->get_PrinterUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_Printers_IIppPrintDevice<D>::GetPrinterAttributesAsBuffer(param::iterable<hstring> const& attributeNames) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice)->GetPrinterAttributesAsBuffer(*(void**)(&attributeNames), &result));
        return winrt::Windows::Storage::Streams::IBuffer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>) consume_Windows_Devices_Printers_IIppPrintDevice<D>::GetPrinterAttributes(param::iterable<hstring> const& attributeNames) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice)->GetPrinterAttributes(*(void**)(&attributeNames), &result));
        return winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppSetAttributesResult) consume_Windows_Devices_Printers_IIppPrintDevice<D>::SetPrinterAttributesFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& printerAttributesBuffer) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice)->SetPrinterAttributesFromBuffer(*(void**)(&printerAttributesBuffer), &result));
        return winrt::Windows::Devices::Printers::IppSetAttributesResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppSetAttributesResult) consume_Windows_Devices_Printers_IIppPrintDevice<D>::SetPrinterAttributes(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const& printerAttributes) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice)->SetPrinterAttributes(*(void**)(&printerAttributes), &result));
        return winrt::Windows::Devices::Printers::IppSetAttributesResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Devices_Printers_IIppPrintDevice2<D>::GetMaxSupportedPdfSize() const
    {
        uint64_t result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice2)->GetMaxSupportedPdfSize(&result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_IIppPrintDevice2<D>::GetMaxSupportedPdfVersion() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice2)->GetMaxSupportedPdfVersion(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Printers_IIppPrintDevice2<D>::IsPdlPassthroughSupported(param::hstring const& pdlContentType) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice2)->IsPdlPassthroughSupported(*(void**)(&pdlContentType), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::PdlPassthroughProvider) consume_Windows_Devices_Printers_IIppPrintDevice2<D>::GetPdlPassthroughProvider() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDevice2)->GetPdlPassthroughProvider(&result));
        return winrt::Windows::Devices::Printers::PdlPassthroughProvider{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_IIppPrintDeviceStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDeviceStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppPrintDevice) consume_Windows_Devices_Printers_IIppPrintDeviceStatics<D>::FromId(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDeviceStatics)->FromId(*(void**)(&deviceId), &result));
        return winrt::Windows::Devices::Printers::IppPrintDevice{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppPrintDevice) consume_Windows_Devices_Printers_IIppPrintDeviceStatics<D>::FromPrinterName(param::hstring const& printerName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDeviceStatics)->FromPrinterName(*(void**)(&printerName), &result));
        return winrt::Windows::Devices::Printers::IppPrintDevice{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Printers_IIppPrintDeviceStatics<D>::IsIppPrinter(param::hstring const& printerName) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppPrintDeviceStatics)->IsIppPrinter(*(void**)(&printerName), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Printers_IIppResolution<D>::Width() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppResolution)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Printers_IIppResolution<D>::Height() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppResolution)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppResolutionUnit) consume_Windows_Devices_Printers_IIppResolution<D>::Unit() const
    {
        winrt::Windows::Devices::Printers::IppResolutionUnit value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppResolution)->get_Unit(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppResolution) consume_Windows_Devices_Printers_IIppResolutionFactory<D>::CreateInstance(int32_t width, int32_t height, winrt::Windows::Devices::Printers::IppResolutionUnit const& unit) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppResolutionFactory)->CreateInstance(width, height, static_cast<int32_t>(unit), &value));
        return winrt::Windows::Devices::Printers::IppResolution{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Printers_IIppSetAttributesResult<D>::Succeeded() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppSetAttributesResult)->get_Succeeded(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Devices::Printers::IppAttributeError>) consume_Windows_Devices_Printers_IIppSetAttributesResult<D>::AttributeErrors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppSetAttributesResult)->get_AttributeErrors(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Devices::Printers::IppAttributeError>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_IIppTextWithLanguage<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppTextWithLanguage)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_IIppTextWithLanguage<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppTextWithLanguage)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppTextWithLanguage) consume_Windows_Devices_Printers_IIppTextWithLanguageFactory<D>::CreateInstance(param::hstring const& language, param::hstring const& text) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IIppTextWithLanguageFactory)->CreateInstance(*(void**)(&language), *(void**)(&text), &value));
        return winrt::Windows::Devices::Printers::IppTextWithLanguage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::PageConfigurationSource) consume_Windows_Devices_Printers_IPageConfigurationSettings<D>::OrientationSource() const
    {
        winrt::Windows::Devices::Printers::PageConfigurationSource value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPageConfigurationSettings)->get_OrientationSource(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_IPageConfigurationSettings<D>::OrientationSource(winrt::Windows::Devices::Printers::PageConfigurationSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPageConfigurationSettings)->put_OrientationSource(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::PageConfigurationSource) consume_Windows_Devices_Printers_IPageConfigurationSettings<D>::SizeSource() const
    {
        winrt::Windows::Devices::Printers::PageConfigurationSource value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPageConfigurationSettings)->get_SizeSource(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_IPageConfigurationSettings<D>::SizeSource(winrt::Windows::Devices::Printers::PageConfigurationSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPageConfigurationSettings)->put_SizeSource(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Devices_Printers_IPdlPassthroughProvider<D>::SupportedPdlContentTypes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPdlPassthroughProvider)->get_SupportedPdlContentTypes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::PdlPassthroughTarget) consume_Windows_Devices_Printers_IPdlPassthroughProvider<D>::StartPrintJobWithTaskOptions(param::hstring const& jobName, param::hstring const& pdlContentType, winrt::Windows::Graphics::Printing::PrintTaskOptions const& taskOptions, winrt::Windows::Devices::Printers::PageConfigurationSettings const& pageConfigurationSettings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPdlPassthroughProvider)->StartPrintJobWithTaskOptions(*(void**)(&jobName), *(void**)(&pdlContentType), *(void**)(&taskOptions), *(void**)(&pageConfigurationSettings), &result));
        return winrt::Windows::Devices::Printers::PdlPassthroughTarget{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::PdlPassthroughTarget) consume_Windows_Devices_Printers_IPdlPassthroughProvider<D>::StartPrintJobWithPrintTicket(param::hstring const& jobName, param::hstring const& pdlContentType, winrt::Windows::Storage::Streams::IInputStream const& printTicket, winrt::Windows::Devices::Printers::PageConfigurationSettings const& pageConfigurationSettings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPdlPassthroughProvider)->StartPrintJobWithPrintTicket(*(void**)(&jobName), *(void**)(&pdlContentType), *(void**)(&printTicket), *(void**)(&pageConfigurationSettings), &result));
        return winrt::Windows::Devices::Printers::PdlPassthroughTarget{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Devices_Printers_IPdlPassthroughTarget<D>::PrintJobId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPdlPassthroughTarget)->get_PrintJobId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Devices_Printers_IPdlPassthroughTarget<D>::GetOutputStream() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPdlPassthroughTarget)->GetOutputStream(&result));
        return winrt::Windows::Storage::Streams::IOutputStream{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_IPdlPassthroughTarget<D>::Submit() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPdlPassthroughTarget)->Submit());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::PrintSchema) consume_Windows_Devices_Printers_IPrint3DDevice<D>::PrintSchema() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPrint3DDevice)->get_PrintSchema(&value));
        return winrt::Windows::Devices::Printers::PrintSchema{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Printers::Print3DDevice>) consume_Windows_Devices_Printers_IPrint3DDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPrint3DDeviceStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Printers::Print3DDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_IPrint3DDeviceStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPrint3DDeviceStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>) consume_Windows_Devices_Printers_IPrintSchema<D>::GetDefaultPrintTicketAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPrintSchema)->GetDefaultPrintTicketAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>) consume_Windows_Devices_Printers_IPrintSchema<D>::GetCapabilitiesAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType const& constrainTicket) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPrintSchema)->GetCapabilitiesAsync(*(void**)(&constrainTicket), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>) consume_Windows_Devices_Printers_IPrintSchema<D>::MergeAndValidateWithDefaultPrintTicketAsync(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType const& deltaTicket) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::IPrintSchema)->MergeAndValidateWithDefaultPrintTicketAsync(*(void**)(&deltaTicket), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppAttributeError> : produce_base<D, winrt::Windows::Devices::Printers::IIppAttributeError>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppAttributeErrorReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUnsupportedValues(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Printers::IppAttributeValue>>(this->shim().GetUnsupportedValues());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppAttributeValue> : produce_base<D, winrt::Windows::Devices::Printers::IIppAttributeValue>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppAttributeValueKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetIntegerArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<int32_t>>(this->shim().GetIntegerArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBooleanArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<bool>>(this->shim().GetBooleanArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetEnumArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<int32_t>>(this->shim().GetEnumArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOctetStringArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().GetOctetStringArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDateTimeArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::DateTime>>(this->shim().GetDateTimeArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetResolutionArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppResolution>>(this->shim().GetResolutionArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetRangeOfIntegerArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppIntegerRange>>(this->shim().GetRangeOfIntegerArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCollectionArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>>>(this->shim().GetCollectionArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTextWithLanguageArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppTextWithLanguage>>(this->shim().GetTextWithLanguageArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNameWithLanguageArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Devices::Printers::IppTextWithLanguage>>(this->shim().GetNameWithLanguageArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTextWithoutLanguageArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetTextWithoutLanguageArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNameWithoutLanguageArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetNameWithoutLanguageArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetKeywordArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetKeywordArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUriArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Foundation::Uri>>(this->shim().GetUriArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetUriSchemaArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetUriSchemaArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCharsetArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetCharsetArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNaturalLanguageArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetNaturalLanguageArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMimeMediaTypeArray(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().GetMimeMediaTypeArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppAttributeValueStatics> : produce_base<D, winrt::Windows::Devices::Printers::IIppAttributeValueStatics>
    {
        int32_t __stdcall CreateUnsupported(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateUnsupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUnknown(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateUnknown());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNoValue(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateNoValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInteger(int32_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateInteger(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateIntegerArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateIntegerArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<int32_t> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBoolean(bool value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateBoolean(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBooleanArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateBooleanArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<bool> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateEnum(int32_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateEnum(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateEnumArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateEnumArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<int32_t> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateOctetString(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateOctetString(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateOctetStringArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateOctetStringArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Storage::Streams::IBuffer> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTime(int64_t value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateDateTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDateTimeArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateDateTimeArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::DateTime> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResolution(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateResolution(*reinterpret_cast<winrt::Windows::Devices::Printers::IppResolution const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateResolutionArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateResolutionArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Printers::IppResolution> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateRangeOfInteger(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateRangeOfInteger(*reinterpret_cast<winrt::Windows::Devices::Printers::IppIntegerRange const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateRangeOfIntegerArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateRangeOfIntegerArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Printers::IppIntegerRange> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCollection(void* memberAttributes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateCollection(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const*>(&memberAttributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCollectionArray(void* memberAttributesArray, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateCollectionArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>>> const*>(&memberAttributesArray)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTextWithLanguage(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateTextWithLanguage(*reinterpret_cast<winrt::Windows::Devices::Printers::IppTextWithLanguage const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTextWithLanguageArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateTextWithLanguageArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Printers::IppTextWithLanguage> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNameWithLanguage(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateNameWithLanguage(*reinterpret_cast<winrt::Windows::Devices::Printers::IppTextWithLanguage const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNameWithLanguageArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateNameWithLanguageArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Printers::IppTextWithLanguage> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTextWithoutLanguage(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateTextWithoutLanguage(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateTextWithoutLanguageArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateTextWithoutLanguageArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNameWithoutLanguage(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateNameWithoutLanguage(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNameWithoutLanguageArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateNameWithoutLanguageArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateKeyword(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateKeyword(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateKeywordArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateKeywordArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUri(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUriArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateUriArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Uri> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUriSchema(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateUriSchema(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUriSchemaArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateUriSchemaArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCharset(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateCharset(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCharsetArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateCharsetArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNaturalLanguage(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateNaturalLanguage(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNaturalLanguageArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateNaturalLanguageArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMimeMedia(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateMimeMedia(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMimeMediaArray(void* values, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppAttributeValue>(this->shim().CreateMimeMediaArray(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppIntegerRange> : produce_base<D, winrt::Windows::Devices::Printers::IIppIntegerRange>
    {
        int32_t __stdcall get_Start(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Start());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_End(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().End());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppIntegerRangeFactory> : produce_base<D, winrt::Windows::Devices::Printers::IIppIntegerRangeFactory>
    {
        int32_t __stdcall CreateInstance(int32_t start, int32_t end, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppIntegerRange>(this->shim().CreateInstance(start, end));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppPrintDevice> : produce_base<D, winrt::Windows::Devices::Printers::IIppPrintDevice>
    {
        int32_t __stdcall get_PrinterName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PrinterName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrinterUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().PrinterUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPrinterAttributesAsBuffer(void* attributeNames, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().GetPrinterAttributesAsBuffer(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&attributeNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPrinterAttributes(void* attributeNames, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IMap<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>>(this->shim().GetPrinterAttributes(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&attributeNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPrinterAttributesFromBuffer(void* printerAttributesBuffer, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppSetAttributesResult>(this->shim().SetPrinterAttributesFromBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&printerAttributesBuffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPrinterAttributes(void* printerAttributes, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppSetAttributesResult>(this->shim().SetPrinterAttributes(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const*>(&printerAttributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppPrintDevice2> : produce_base<D, winrt::Windows::Devices::Printers::IIppPrintDevice2>
    {
        int32_t __stdcall GetMaxSupportedPdfSize(uint64_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<uint64_t>(this->shim().GetMaxSupportedPdfSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMaxSupportedPdfVersion(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetMaxSupportedPdfVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsPdlPassthroughSupported(void* pdlContentType, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsPdlPassthroughSupported(*reinterpret_cast<hstring const*>(&pdlContentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPdlPassthroughProvider(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::PdlPassthroughProvider>(this->shim().GetPdlPassthroughProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppPrintDeviceStatics> : produce_base<D, winrt::Windows::Devices::Printers::IIppPrintDeviceStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromId(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppPrintDevice>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromPrinterName(void* printerName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::IppPrintDevice>(this->shim().FromPrinterName(*reinterpret_cast<hstring const*>(&printerName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsIppPrinter(void* printerName, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsIppPrinter(*reinterpret_cast<hstring const*>(&printerName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppResolution> : produce_base<D, winrt::Windows::Devices::Printers::IIppResolution>
    {
        int32_t __stdcall get_Width(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Unit(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppResolutionUnit>(this->shim().Unit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppResolutionFactory> : produce_base<D, winrt::Windows::Devices::Printers::IIppResolutionFactory>
    {
        int32_t __stdcall CreateInstance(int32_t width, int32_t height, int32_t unit, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppResolution>(this->shim().CreateInstance(width, height, *reinterpret_cast<winrt::Windows::Devices::Printers::IppResolutionUnit const*>(&unit)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppSetAttributesResult> : produce_base<D, winrt::Windows::Devices::Printers::IIppSetAttributesResult>
    {
        int32_t __stdcall get_Succeeded(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AttributeErrors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Devices::Printers::IppAttributeError>>(this->shim().AttributeErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppTextWithLanguage> : produce_base<D, winrt::Windows::Devices::Printers::IIppTextWithLanguage>
    {
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IIppTextWithLanguageFactory> : produce_base<D, winrt::Windows::Devices::Printers::IIppTextWithLanguageFactory>
    {
        int32_t __stdcall CreateInstance(void* language, void* text, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppTextWithLanguage>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&language), *reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IPageConfigurationSettings> : produce_base<D, winrt::Windows::Devices::Printers::IPageConfigurationSettings>
    {
        int32_t __stdcall get_OrientationSource(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::PageConfigurationSource>(this->shim().OrientationSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OrientationSource(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OrientationSource(*reinterpret_cast<winrt::Windows::Devices::Printers::PageConfigurationSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SizeSource(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::PageConfigurationSource>(this->shim().SizeSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SizeSource(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SizeSource(*reinterpret_cast<winrt::Windows::Devices::Printers::PageConfigurationSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IPdlPassthroughProvider> : produce_base<D, winrt::Windows::Devices::Printers::IPdlPassthroughProvider>
    {
        int32_t __stdcall get_SupportedPdlContentTypes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedPdlContentTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPrintJobWithTaskOptions(void* jobName, void* pdlContentType, void* taskOptions, void* pageConfigurationSettings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::PdlPassthroughTarget>(this->shim().StartPrintJobWithTaskOptions(*reinterpret_cast<hstring const*>(&jobName), *reinterpret_cast<hstring const*>(&pdlContentType), *reinterpret_cast<winrt::Windows::Graphics::Printing::PrintTaskOptions const*>(&taskOptions), *reinterpret_cast<winrt::Windows::Devices::Printers::PageConfigurationSettings const*>(&pageConfigurationSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartPrintJobWithPrintTicket(void* jobName, void* pdlContentType, void* printTicket, void* pageConfigurationSettings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Printers::PdlPassthroughTarget>(this->shim().StartPrintJobWithPrintTicket(*reinterpret_cast<hstring const*>(&jobName), *reinterpret_cast<hstring const*>(&pdlContentType), *reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&printTicket), *reinterpret_cast<winrt::Windows::Devices::Printers::PageConfigurationSettings const*>(&pageConfigurationSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IPdlPassthroughTarget> : produce_base<D, winrt::Windows::Devices::Printers::IPdlPassthroughTarget>
    {
        int32_t __stdcall get_PrintJobId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PrintJobId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOutputStream(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().GetOutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Submit() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Submit();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IPrint3DDevice> : produce_base<D, winrt::Windows::Devices::Printers::IPrint3DDevice>
    {
        int32_t __stdcall get_PrintSchema(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::PrintSchema>(this->shim().PrintSchema());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IPrint3DDeviceStatics> : produce_base<D, winrt::Windows::Devices::Printers::IPrint3DDeviceStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Printers::Print3DDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::IPrintSchema> : produce_base<D, winrt::Windows::Devices::Printers::IPrintSchema>
    {
        int32_t __stdcall GetDefaultPrintTicketAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().GetDefaultPrintTicketAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCapabilitiesAsync(void* constrainTicket, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().GetCapabilitiesAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType const*>(&constrainTicket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MergeAndValidateWithDefaultPrintTicketAsync(void* deltaTicket, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().MergeAndValidateWithDefaultPrintTicketAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType const*>(&deltaTicket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Printers
{
    inline auto IppAttributeValue::CreateUnsupported()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Printers::IppAttributeValue(*)(IIppAttributeValueStatics const&), IppAttributeValue, IIppAttributeValueStatics>([](IIppAttributeValueStatics const& f) { return f.CreateUnsupported(); });
    }
    inline auto IppAttributeValue::CreateUnknown()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Printers::IppAttributeValue(*)(IIppAttributeValueStatics const&), IppAttributeValue, IIppAttributeValueStatics>([](IIppAttributeValueStatics const& f) { return f.CreateUnknown(); });
    }
    inline auto IppAttributeValue::CreateNoValue()
    {
        return impl::call_factory_cast<winrt::Windows::Devices::Printers::IppAttributeValue(*)(IIppAttributeValueStatics const&), IppAttributeValue, IIppAttributeValueStatics>([](IIppAttributeValueStatics const& f) { return f.CreateNoValue(); });
    }
    inline auto IppAttributeValue::CreateInteger(int32_t value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateInteger(value); });
    }
    inline auto IppAttributeValue::CreateIntegerArray(param::iterable<int32_t> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateIntegerArray(values); });
    }
    inline auto IppAttributeValue::CreateBoolean(bool value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateBoolean(value); });
    }
    inline auto IppAttributeValue::CreateBooleanArray(param::iterable<bool> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateBooleanArray(values); });
    }
    inline auto IppAttributeValue::CreateEnum(int32_t value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateEnum(value); });
    }
    inline auto IppAttributeValue::CreateEnumArray(param::iterable<int32_t> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateEnumArray(values); });
    }
    inline auto IppAttributeValue::CreateOctetString(winrt::Windows::Storage::Streams::IBuffer const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateOctetString(value); });
    }
    inline auto IppAttributeValue::CreateOctetStringArray(param::iterable<winrt::Windows::Storage::Streams::IBuffer> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateOctetStringArray(values); });
    }
    inline auto IppAttributeValue::CreateDateTime(winrt::Windows::Foundation::DateTime const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateDateTime(value); });
    }
    inline auto IppAttributeValue::CreateDateTimeArray(param::iterable<winrt::Windows::Foundation::DateTime> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateDateTimeArray(values); });
    }
    inline auto IppAttributeValue::CreateResolution(winrt::Windows::Devices::Printers::IppResolution const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateResolution(value); });
    }
    inline auto IppAttributeValue::CreateResolutionArray(param::iterable<winrt::Windows::Devices::Printers::IppResolution> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateResolutionArray(values); });
    }
    inline auto IppAttributeValue::CreateRangeOfInteger(winrt::Windows::Devices::Printers::IppIntegerRange const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateRangeOfInteger(value); });
    }
    inline auto IppAttributeValue::CreateRangeOfIntegerArray(param::iterable<winrt::Windows::Devices::Printers::IppIntegerRange> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateRangeOfIntegerArray(values); });
    }
    inline auto IppAttributeValue::CreateCollection(param::iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>> const& memberAttributes)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateCollection(memberAttributes); });
    }
    inline auto IppAttributeValue::CreateCollectionArray(param::iterable<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, winrt::Windows::Devices::Printers::IppAttributeValue>>> const& memberAttributesArray)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateCollectionArray(memberAttributesArray); });
    }
    inline auto IppAttributeValue::CreateTextWithLanguage(winrt::Windows::Devices::Printers::IppTextWithLanguage const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateTextWithLanguage(value); });
    }
    inline auto IppAttributeValue::CreateTextWithLanguageArray(param::iterable<winrt::Windows::Devices::Printers::IppTextWithLanguage> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateTextWithLanguageArray(values); });
    }
    inline auto IppAttributeValue::CreateNameWithLanguage(winrt::Windows::Devices::Printers::IppTextWithLanguage const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateNameWithLanguage(value); });
    }
    inline auto IppAttributeValue::CreateNameWithLanguageArray(param::iterable<winrt::Windows::Devices::Printers::IppTextWithLanguage> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateNameWithLanguageArray(values); });
    }
    inline auto IppAttributeValue::CreateTextWithoutLanguage(param::hstring const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateTextWithoutLanguage(value); });
    }
    inline auto IppAttributeValue::CreateTextWithoutLanguageArray(param::iterable<hstring> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateTextWithoutLanguageArray(values); });
    }
    inline auto IppAttributeValue::CreateNameWithoutLanguage(param::hstring const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateNameWithoutLanguage(value); });
    }
    inline auto IppAttributeValue::CreateNameWithoutLanguageArray(param::iterable<hstring> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateNameWithoutLanguageArray(values); });
    }
    inline auto IppAttributeValue::CreateKeyword(param::hstring const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateKeyword(value); });
    }
    inline auto IppAttributeValue::CreateKeywordArray(param::iterable<hstring> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateKeywordArray(values); });
    }
    inline auto IppAttributeValue::CreateUri(winrt::Windows::Foundation::Uri const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateUri(value); });
    }
    inline auto IppAttributeValue::CreateUriArray(param::iterable<winrt::Windows::Foundation::Uri> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateUriArray(values); });
    }
    inline auto IppAttributeValue::CreateUriSchema(param::hstring const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateUriSchema(value); });
    }
    inline auto IppAttributeValue::CreateUriSchemaArray(param::iterable<hstring> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateUriSchemaArray(values); });
    }
    inline auto IppAttributeValue::CreateCharset(param::hstring const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateCharset(value); });
    }
    inline auto IppAttributeValue::CreateCharsetArray(param::iterable<hstring> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateCharsetArray(values); });
    }
    inline auto IppAttributeValue::CreateNaturalLanguage(param::hstring const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateNaturalLanguage(value); });
    }
    inline auto IppAttributeValue::CreateNaturalLanguageArray(param::iterable<hstring> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateNaturalLanguageArray(values); });
    }
    inline auto IppAttributeValue::CreateMimeMedia(param::hstring const& value)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateMimeMedia(value); });
    }
    inline auto IppAttributeValue::CreateMimeMediaArray(param::iterable<hstring> const& values)
    {
        return impl::call_factory<IppAttributeValue, IIppAttributeValueStatics>([&](IIppAttributeValueStatics const& f) { return f.CreateMimeMediaArray(values); });
    }
    inline IppIntegerRange::IppIntegerRange(int32_t start, int32_t end) :
        IppIntegerRange(impl::call_factory<IppIntegerRange, IIppIntegerRangeFactory>([&](IIppIntegerRangeFactory const& f) { return f.CreateInstance(start, end); }))
    {
    }
    inline auto IppPrintDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IIppPrintDeviceStatics const&), IppPrintDevice, IIppPrintDeviceStatics>([](IIppPrintDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto IppPrintDevice::FromId(param::hstring const& deviceId)
    {
        return impl::call_factory<IppPrintDevice, IIppPrintDeviceStatics>([&](IIppPrintDeviceStatics const& f) { return f.FromId(deviceId); });
    }
    inline auto IppPrintDevice::FromPrinterName(param::hstring const& printerName)
    {
        return impl::call_factory<IppPrintDevice, IIppPrintDeviceStatics>([&](IIppPrintDeviceStatics const& f) { return f.FromPrinterName(printerName); });
    }
    inline auto IppPrintDevice::IsIppPrinter(param::hstring const& printerName)
    {
        return impl::call_factory<IppPrintDevice, IIppPrintDeviceStatics>([&](IIppPrintDeviceStatics const& f) { return f.IsIppPrinter(printerName); });
    }
    inline IppResolution::IppResolution(int32_t width, int32_t height, winrt::Windows::Devices::Printers::IppResolutionUnit const& unit) :
        IppResolution(impl::call_factory<IppResolution, IIppResolutionFactory>([&](IIppResolutionFactory const& f) { return f.CreateInstance(width, height, unit); }))
    {
    }
    inline IppTextWithLanguage::IppTextWithLanguage(param::hstring const& language, param::hstring const& text) :
        IppTextWithLanguage(impl::call_factory<IppTextWithLanguage, IIppTextWithLanguageFactory>([&](IIppTextWithLanguageFactory const& f) { return f.CreateInstance(language, text); }))
    {
    }
    inline PageConfigurationSettings::PageConfigurationSettings() :
        PageConfigurationSettings(impl::call_factory_cast<PageConfigurationSettings(*)(winrt::Windows::Foundation::IActivationFactory const&), PageConfigurationSettings>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PageConfigurationSettings>(); }))
    {
    }
    inline auto Print3DDevice::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<Print3DDevice, IPrint3DDeviceStatics>([&](IPrint3DDeviceStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto Print3DDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IPrint3DDeviceStatics const&), Print3DDevice, IPrint3DDeviceStatics>([](IPrint3DDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Printers::IIppAttributeError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppAttributeValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppAttributeValueStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppIntegerRange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppIntegerRangeFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppPrintDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppPrintDevice2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppPrintDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppResolution> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppResolutionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppSetAttributesResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppTextWithLanguage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IIppTextWithLanguageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IPageConfigurationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IPdlPassthroughProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IPdlPassthroughTarget> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IPrint3DDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IPrint3DDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IPrintSchema> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IppAttributeError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IppAttributeValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IppIntegerRange> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IppPrintDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IppResolution> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IppSetAttributesResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::IppTextWithLanguage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::PageConfigurationSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::PdlPassthroughProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::PdlPassthroughTarget> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Print3DDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::PrintSchema> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
