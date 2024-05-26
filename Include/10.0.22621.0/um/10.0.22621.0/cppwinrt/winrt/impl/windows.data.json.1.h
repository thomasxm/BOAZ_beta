// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Json_1_H
#define WINRT_Windows_Data_Json_1_H
#include "winrt/impl/Windows.Data.Json.0.h"
WINRT_EXPORT namespace winrt::Windows::Data::Json
{
    struct __declspec(empty_bases) IJsonArray :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonArray>,
        impl::require<winrt::Windows::Data::Json::IJsonArray, winrt::Windows::Data::Json::IJsonValue>
    {
        IJsonArray(std::nullptr_t = nullptr) noexcept {}
        IJsonArray(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJsonArrayStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonArrayStatics>
    {
        IJsonArrayStatics(std::nullptr_t = nullptr) noexcept {}
        IJsonArrayStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJsonErrorStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonErrorStatics2>
    {
        IJsonErrorStatics2(std::nullptr_t = nullptr) noexcept {}
        IJsonErrorStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJsonObject :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonObject>,
        impl::require<winrt::Windows::Data::Json::IJsonObject, winrt::Windows::Data::Json::IJsonValue>
    {
        IJsonObject(std::nullptr_t = nullptr) noexcept {}
        IJsonObject(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJsonObjectStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonObjectStatics>
    {
        IJsonObjectStatics(std::nullptr_t = nullptr) noexcept {}
        IJsonObjectStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJsonObjectWithDefaultValues :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonObjectWithDefaultValues>,
        impl::require<winrt::Windows::Data::Json::IJsonObjectWithDefaultValues, winrt::Windows::Data::Json::IJsonValue, winrt::Windows::Data::Json::IJsonObject>
    {
        IJsonObjectWithDefaultValues(std::nullptr_t = nullptr) noexcept {}
        IJsonObjectWithDefaultValues(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IJsonObjectWithDefaultValues, IJsonObjectWithDefaultValues>::GetNamedArray;
        using impl::consume_t<IJsonObjectWithDefaultValues, winrt::Windows::Data::Json::IJsonObject>::GetNamedArray;
        using impl::consume_t<IJsonObjectWithDefaultValues, IJsonObjectWithDefaultValues>::GetNamedBoolean;
        using impl::consume_t<IJsonObjectWithDefaultValues, winrt::Windows::Data::Json::IJsonObject>::GetNamedBoolean;
        using impl::consume_t<IJsonObjectWithDefaultValues, IJsonObjectWithDefaultValues>::GetNamedNumber;
        using impl::consume_t<IJsonObjectWithDefaultValues, winrt::Windows::Data::Json::IJsonObject>::GetNamedNumber;
        using impl::consume_t<IJsonObjectWithDefaultValues, IJsonObjectWithDefaultValues>::GetNamedObject;
        using impl::consume_t<IJsonObjectWithDefaultValues, winrt::Windows::Data::Json::IJsonObject>::GetNamedObject;
        using impl::consume_t<IJsonObjectWithDefaultValues, IJsonObjectWithDefaultValues>::GetNamedString;
        using impl::consume_t<IJsonObjectWithDefaultValues, winrt::Windows::Data::Json::IJsonObject>::GetNamedString;
        using impl::consume_t<IJsonObjectWithDefaultValues, IJsonObjectWithDefaultValues>::GetNamedValue;
        using impl::consume_t<IJsonObjectWithDefaultValues, winrt::Windows::Data::Json::IJsonObject>::GetNamedValue;
    };
    struct __declspec(empty_bases) IJsonValue :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonValue>
    {
        IJsonValue(std::nullptr_t = nullptr) noexcept {}
        IJsonValue(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJsonValueStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonValueStatics>
    {
        IJsonValueStatics(std::nullptr_t = nullptr) noexcept {}
        IJsonValueStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IJsonValueStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IJsonValueStatics2>
    {
        IJsonValueStatics2(std::nullptr_t = nullptr) noexcept {}
        IJsonValueStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
