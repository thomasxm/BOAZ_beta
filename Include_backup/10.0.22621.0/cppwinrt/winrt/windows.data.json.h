// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Json_H
#define WINRT_Windows_Data_Json_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Data.Json.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonObject) consume_Windows_Data_Json_IJsonArray<D>::GetObjectAt(uint32_t index) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonArray)->GetObjectAt(index, &returnValue));
        return winrt::Windows::Data::Json::JsonObject{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonArray) consume_Windows_Data_Json_IJsonArray<D>::GetArrayAt(uint32_t index) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonArray)->GetArrayAt(index, &returnValue));
        return winrt::Windows::Data::Json::JsonArray{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Data_Json_IJsonArray<D>::GetStringAt(uint32_t index) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonArray)->GetStringAt(index, &returnValue));
        return hstring{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Data_Json_IJsonArray<D>::GetNumberAt(uint32_t index) const
    {
        double returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonArray)->GetNumberAt(index, &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Json_IJsonArray<D>::GetBooleanAt(uint32_t index) const
    {
        bool returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonArray)->GetBooleanAt(index, &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonArray) consume_Windows_Data_Json_IJsonArrayStatics<D>::Parse(param::hstring const& input) const
    {
        void* jsonArray{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonArrayStatics)->Parse(*(void**)(&input), &jsonArray));
        return winrt::Windows::Data::Json::JsonArray{ jsonArray, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Json_IJsonArrayStatics<D>::TryParse(param::hstring const& input, winrt::Windows::Data::Json::JsonArray& result) const
    {
        bool succeeded{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonArrayStatics)->TryParse(*(void**)(&input), impl::bind_out(result), &succeeded));
        return succeeded;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonErrorStatus) consume_Windows_Data_Json_IJsonErrorStatics2<D>::GetJsonStatus(int32_t hresult) const
    {
        winrt::Windows::Data::Json::JsonErrorStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonErrorStatics2)->GetJsonStatus(hresult, reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValue) consume_Windows_Data_Json_IJsonObject<D>::GetNamedValue(param::hstring const& name) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObject)->GetNamedValue(*(void**)(&name), &returnValue));
        return winrt::Windows::Data::Json::JsonValue{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Data_Json_IJsonObject<D>::SetNamedValue(param::hstring const& name, winrt::Windows::Data::Json::IJsonValue const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObject)->SetNamedValue(*(void**)(&name), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonObject) consume_Windows_Data_Json_IJsonObject<D>::GetNamedObject(param::hstring const& name) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObject)->GetNamedObject(*(void**)(&name), &returnValue));
        return winrt::Windows::Data::Json::JsonObject{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonArray) consume_Windows_Data_Json_IJsonObject<D>::GetNamedArray(param::hstring const& name) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObject)->GetNamedArray(*(void**)(&name), &returnValue));
        return winrt::Windows::Data::Json::JsonArray{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Data_Json_IJsonObject<D>::GetNamedString(param::hstring const& name) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObject)->GetNamedString(*(void**)(&name), &returnValue));
        return hstring{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Data_Json_IJsonObject<D>::GetNamedNumber(param::hstring const& name) const
    {
        double returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObject)->GetNamedNumber(*(void**)(&name), &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Json_IJsonObject<D>::GetNamedBoolean(param::hstring const& name) const
    {
        bool returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObject)->GetNamedBoolean(*(void**)(&name), &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonObject) consume_Windows_Data_Json_IJsonObjectStatics<D>::Parse(param::hstring const& input) const
    {
        void* jsonObject{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectStatics)->Parse(*(void**)(&input), &jsonObject));
        return winrt::Windows::Data::Json::JsonObject{ jsonObject, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Json_IJsonObjectStatics<D>::TryParse(param::hstring const& input, winrt::Windows::Data::Json::JsonObject& result) const
    {
        bool succeeded{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectStatics)->TryParse(*(void**)(&input), impl::bind_out(result), &succeeded));
        return succeeded;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValue) consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedValue(param::hstring const& name, winrt::Windows::Data::Json::JsonValue const& defaultValue) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedValueOrDefault(*(void**)(&name), *(void**)(&defaultValue), &returnValue));
        return winrt::Windows::Data::Json::JsonValue{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonObject) consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedObject(param::hstring const& name, winrt::Windows::Data::Json::JsonObject const& defaultValue) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedObjectOrDefault(*(void**)(&name), *(void**)(&defaultValue), &returnValue));
        return winrt::Windows::Data::Json::JsonObject{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedString(param::hstring const& name, param::hstring const& defaultValue) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedStringOrDefault(*(void**)(&name), *(void**)(&defaultValue), &returnValue));
        return hstring{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonArray) consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedArray(param::hstring const& name, winrt::Windows::Data::Json::JsonArray const& defaultValue) const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedArrayOrDefault(*(void**)(&name), *(void**)(&defaultValue), &returnValue));
        return winrt::Windows::Data::Json::JsonArray{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedNumber(param::hstring const& name, double defaultValue) const
    {
        double returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedNumberOrDefault(*(void**)(&name), defaultValue, &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Json_IJsonObjectWithDefaultValues<D>::GetNamedBoolean(param::hstring const& name, bool defaultValue) const
    {
        bool returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonObjectWithDefaultValues)->GetNamedBooleanOrDefault(*(void**)(&name), defaultValue, &returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValueType) consume_Windows_Data_Json_IJsonValue<D>::ValueType() const
    {
        winrt::Windows::Data::Json::JsonValueType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValue)->get_ValueType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Data_Json_IJsonValue<D>::Stringify() const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValue)->Stringify(&returnValue));
        return hstring{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Data_Json_IJsonValue<D>::GetString() const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValue)->GetString(&returnValue));
        return hstring{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Data_Json_IJsonValue<D>::GetNumber() const
    {
        double returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValue)->GetNumber(&returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Json_IJsonValue<D>::GetBoolean() const
    {
        bool returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValue)->GetBoolean(&returnValue));
        return returnValue;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonArray) consume_Windows_Data_Json_IJsonValue<D>::GetArray() const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValue)->GetArray(&returnValue));
        return winrt::Windows::Data::Json::JsonArray{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonObject) consume_Windows_Data_Json_IJsonValue<D>::GetObject() const
    {
        void* returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValue)->GetObject(&returnValue));
        return winrt::Windows::Data::Json::JsonObject{ returnValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValue) consume_Windows_Data_Json_IJsonValueStatics<D>::Parse(param::hstring const& input) const
    {
        void* jsonValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValueStatics)->Parse(*(void**)(&input), &jsonValue));
        return winrt::Windows::Data::Json::JsonValue{ jsonValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Data_Json_IJsonValueStatics<D>::TryParse(param::hstring const& input, winrt::Windows::Data::Json::JsonValue& result) const
    {
        bool succeeded{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValueStatics)->TryParse(*(void**)(&input), impl::bind_out(result), &succeeded));
        return succeeded;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValue) consume_Windows_Data_Json_IJsonValueStatics<D>::CreateBooleanValue(bool input) const
    {
        void* jsonValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValueStatics)->CreateBooleanValue(input, &jsonValue));
        return winrt::Windows::Data::Json::JsonValue{ jsonValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValue) consume_Windows_Data_Json_IJsonValueStatics<D>::CreateNumberValue(double input) const
    {
        void* jsonValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValueStatics)->CreateNumberValue(input, &jsonValue));
        return winrt::Windows::Data::Json::JsonValue{ jsonValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValue) consume_Windows_Data_Json_IJsonValueStatics<D>::CreateStringValue(param::hstring const& input) const
    {
        void* jsonValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValueStatics)->CreateStringValue(*(void**)(&input), &jsonValue));
        return winrt::Windows::Data::Json::JsonValue{ jsonValue, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Json::JsonValue) consume_Windows_Data_Json_IJsonValueStatics2<D>::CreateNullValue() const
    {
        void* jsonValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Data::Json::IJsonValueStatics2)->CreateNullValue(&jsonValue));
        return winrt::Windows::Data::Json::JsonValue{ jsonValue, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonArray> : produce_base<D, winrt::Windows::Data::Json::IJsonArray>
    {
        int32_t __stdcall GetObjectAt(uint32_t index, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonObject>(this->shim().GetObjectAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetArrayAt(uint32_t index, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonArray>(this->shim().GetArrayAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetStringAt(uint32_t index, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<hstring>(this->shim().GetStringAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNumberAt(uint32_t index, double* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<double>(this->shim().GetNumberAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBooleanAt(uint32_t index, bool* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<bool>(this->shim().GetBooleanAt(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonArrayStatics> : produce_base<D, winrt::Windows::Data::Json::IJsonArrayStatics>
    {
        int32_t __stdcall Parse(void* input, void** jsonArray) noexcept final try
        {
            clear_abi(jsonArray);
            typename D::abi_guard guard(this->shim());
            *jsonArray = detach_from<winrt::Windows::Data::Json::JsonArray>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryParse(void* input, void** result, bool* succeeded) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<winrt::Windows::Data::Json::JsonArray*>(result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonErrorStatics2> : produce_base<D, winrt::Windows::Data::Json::IJsonErrorStatics2>
    {
        int32_t __stdcall GetJsonStatus(int32_t hresult, int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Data::Json::JsonErrorStatus>(this->shim().GetJsonStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonObject> : produce_base<D, winrt::Windows::Data::Json::IJsonObject>
    {
        int32_t __stdcall GetNamedValue(void* name, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonValue>(this->shim().GetNamedValue(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetNamedValue(void* name, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetNamedValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Data::Json::IJsonValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedObject(void* name, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonObject>(this->shim().GetNamedObject(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedArray(void* name, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonArray>(this->shim().GetNamedArray(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedString(void* name, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<hstring>(this->shim().GetNamedString(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedNumber(void* name, double* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<double>(this->shim().GetNamedNumber(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedBoolean(void* name, bool* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<bool>(this->shim().GetNamedBoolean(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonObjectStatics> : produce_base<D, winrt::Windows::Data::Json::IJsonObjectStatics>
    {
        int32_t __stdcall Parse(void* input, void** jsonObject) noexcept final try
        {
            clear_abi(jsonObject);
            typename D::abi_guard guard(this->shim());
            *jsonObject = detach_from<winrt::Windows::Data::Json::JsonObject>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryParse(void* input, void** result, bool* succeeded) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<winrt::Windows::Data::Json::JsonObject*>(result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonObjectWithDefaultValues> : produce_base<D, winrt::Windows::Data::Json::IJsonObjectWithDefaultValues>
    {
        int32_t __stdcall GetNamedValueOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonValue>(this->shim().GetNamedValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Data::Json::JsonValue const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedObjectOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonObject>(this->shim().GetNamedObject(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Data::Json::JsonObject const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedStringOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<hstring>(this->shim().GetNamedString(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedArrayOrDefault(void* name, void* defaultValue, void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonArray>(this->shim().GetNamedArray(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::Windows::Data::Json::JsonArray const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedNumberOrDefault(void* name, double defaultValue, double* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<double>(this->shim().GetNamedNumber(*reinterpret_cast<hstring const*>(&name), defaultValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNamedBooleanOrDefault(void* name, bool defaultValue, bool* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<bool>(this->shim().GetNamedBoolean(*reinterpret_cast<hstring const*>(&name), defaultValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonValue> : produce_base<D, winrt::Windows::Data::Json::IJsonValue>
    {
        int32_t __stdcall get_ValueType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Json::JsonValueType>(this->shim().ValueType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stringify(void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<hstring>(this->shim().Stringify());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetString(void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<hstring>(this->shim().GetString());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetNumber(double* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<double>(this->shim().GetNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetBoolean(bool* returnValue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<bool>(this->shim().GetBoolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetArray(void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonArray>(this->shim().GetArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetObject(void** returnValue) noexcept final try
        {
            clear_abi(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::Windows::Data::Json::JsonObject>(this->shim().GetObject());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonValueStatics> : produce_base<D, winrt::Windows::Data::Json::IJsonValueStatics>
    {
        int32_t __stdcall Parse(void* input, void** jsonValue) noexcept final try
        {
            clear_abi(jsonValue);
            typename D::abi_guard guard(this->shim());
            *jsonValue = detach_from<winrt::Windows::Data::Json::JsonValue>(this->shim().Parse(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryParse(void* input, void** result, bool* succeeded) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *succeeded = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<hstring const*>(&input), *reinterpret_cast<winrt::Windows::Data::Json::JsonValue*>(result)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBooleanValue(bool input, void** jsonValue) noexcept final try
        {
            clear_abi(jsonValue);
            typename D::abi_guard guard(this->shim());
            *jsonValue = detach_from<winrt::Windows::Data::Json::JsonValue>(this->shim().CreateBooleanValue(input));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateNumberValue(double input, void** jsonValue) noexcept final try
        {
            clear_abi(jsonValue);
            typename D::abi_guard guard(this->shim());
            *jsonValue = detach_from<winrt::Windows::Data::Json::JsonValue>(this->shim().CreateNumberValue(input));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateStringValue(void* input, void** jsonValue) noexcept final try
        {
            clear_abi(jsonValue);
            typename D::abi_guard guard(this->shim());
            *jsonValue = detach_from<winrt::Windows::Data::Json::JsonValue>(this->shim().CreateStringValue(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Data::Json::IJsonValueStatics2> : produce_base<D, winrt::Windows::Data::Json::IJsonValueStatics2>
    {
        int32_t __stdcall CreateNullValue(void** jsonValue) noexcept final try
        {
            clear_abi(jsonValue);
            typename D::abi_guard guard(this->shim());
            *jsonValue = detach_from<winrt::Windows::Data::Json::JsonValue>(this->shim().CreateNullValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Data::Json
{
    inline JsonArray::JsonArray() :
        JsonArray(impl::call_factory_cast<JsonArray(*)(winrt::Windows::Foundation::IActivationFactory const&), JsonArray>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<JsonArray>(); }))
    {
    }
    inline auto JsonArray::Parse(param::hstring const& input)
    {
        return impl::call_factory<JsonArray, IJsonArrayStatics>([&](IJsonArrayStatics const& f) { return f.Parse(input); });
    }
    inline auto JsonArray::TryParse(param::hstring const& input, winrt::Windows::Data::Json::JsonArray& result)
    {
        return impl::call_factory<JsonArray, IJsonArrayStatics>([&](IJsonArrayStatics const& f) { return f.TryParse(input, result); });
    }
    inline auto JsonError::GetJsonStatus(int32_t hresult)
    {
        return impl::call_factory<JsonError, IJsonErrorStatics2>([&](IJsonErrorStatics2 const& f) { return f.GetJsonStatus(hresult); });
    }
    inline JsonObject::JsonObject() :
        JsonObject(impl::call_factory_cast<JsonObject(*)(winrt::Windows::Foundation::IActivationFactory const&), JsonObject>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<JsonObject>(); }))
    {
    }
    inline auto JsonObject::Parse(param::hstring const& input)
    {
        return impl::call_factory<JsonObject, IJsonObjectStatics>([&](IJsonObjectStatics const& f) { return f.Parse(input); });
    }
    inline auto JsonObject::TryParse(param::hstring const& input, winrt::Windows::Data::Json::JsonObject& result)
    {
        return impl::call_factory<JsonObject, IJsonObjectStatics>([&](IJsonObjectStatics const& f) { return f.TryParse(input, result); });
    }
    inline auto JsonValue::Parse(param::hstring const& input)
    {
        return impl::call_factory<JsonValue, IJsonValueStatics>([&](IJsonValueStatics const& f) { return f.Parse(input); });
    }
    inline auto JsonValue::TryParse(param::hstring const& input, winrt::Windows::Data::Json::JsonValue& result)
    {
        return impl::call_factory<JsonValue, IJsonValueStatics>([&](IJsonValueStatics const& f) { return f.TryParse(input, result); });
    }
    inline auto JsonValue::CreateBooleanValue(bool input)
    {
        return impl::call_factory<JsonValue, IJsonValueStatics>([&](IJsonValueStatics const& f) { return f.CreateBooleanValue(input); });
    }
    inline auto JsonValue::CreateNumberValue(double input)
    {
        return impl::call_factory<JsonValue, IJsonValueStatics>([&](IJsonValueStatics const& f) { return f.CreateNumberValue(input); });
    }
    inline auto JsonValue::CreateStringValue(param::hstring const& input)
    {
        return impl::call_factory<JsonValue, IJsonValueStatics>([&](IJsonValueStatics const& f) { return f.CreateStringValue(input); });
    }
    inline auto JsonValue::CreateNullValue()
    {
        return impl::call_factory_cast<winrt::Windows::Data::Json::JsonValue(*)(IJsonValueStatics2 const&), JsonValue, IJsonValueStatics2>([](IJsonValueStatics2 const& f) { return f.CreateNullValue(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Data::Json::IJsonArray> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonArrayStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonErrorStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonObjectStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonObjectWithDefaultValues> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonValueStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::IJsonValueStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::JsonArray> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::JsonError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::JsonObject> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Data::Json::JsonValue> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
    template<> struct formatter<winrt::Windows::Data::Json::JsonArray, wchar_t> : formatter<winrt::Windows::Foundation::IStringable, wchar_t> {};
    template<> struct formatter<winrt::Windows::Data::Json::JsonObject, wchar_t> : formatter<winrt::Windows::Foundation::IStringable, wchar_t> {};
    template<> struct formatter<winrt::Windows::Data::Json::JsonValue, wchar_t> : formatter<winrt::Windows::Foundation::IStringable, wchar_t> {};
#endif
}
#endif
