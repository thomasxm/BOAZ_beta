// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Streams_H
#define WINRT_Windows_Storage_Streams_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Storage.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_Streams_IBuffer<D>::Capacity() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IBuffer)->get_Capacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_Streams_IBuffer<D>::Length() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IBuffer)->get_Length(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IBuffer<D>::Length(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IBuffer)->put_Length(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::Buffer) consume_Windows_Storage_Streams_IBufferFactory<D>::Create(uint32_t capacity) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IBufferFactory)->Create(capacity, &value));
        return winrt::Windows::Storage::Streams::Buffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::Buffer) consume_Windows_Storage_Streams_IBufferStatics<D>::CreateCopyFromMemoryBuffer(winrt::Windows::Foundation::IMemoryBuffer const& input) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IBufferStatics)->CreateCopyFromMemoryBuffer(*(void**)(&input), &value));
        return winrt::Windows::Storage::Streams::Buffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::MemoryBuffer) consume_Windows_Storage_Streams_IBufferStatics<D>::CreateMemoryBufferOverIBuffer(winrt::Windows::Storage::Streams::IBuffer const& input) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IBufferStatics)->CreateMemoryBufferOverIBuffer(*(void**)(&input), &value));
        return winrt::Windows::Foundation::MemoryBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Streams_IContentTypeProvider<D>::ContentType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IContentTypeProvider)->get_ContentType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_Streams_IDataReader<D>::UnconsumedBufferLength() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->get_UnconsumedBufferLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::UnicodeEncoding) consume_Windows_Storage_Streams_IDataReader<D>::UnicodeEncoding() const
    {
        winrt::Windows::Storage::Streams::UnicodeEncoding value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->get_UnicodeEncoding(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataReader<D>::UnicodeEncoding(winrt::Windows::Storage::Streams::UnicodeEncoding const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->put_UnicodeEncoding(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::ByteOrder) consume_Windows_Storage_Streams_IDataReader<D>::ByteOrder() const
    {
        winrt::Windows::Storage::Streams::ByteOrder value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->get_ByteOrder(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataReader<D>::ByteOrder(winrt::Windows::Storage::Streams::ByteOrder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->put_ByteOrder(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::InputStreamOptions) consume_Windows_Storage_Streams_IDataReader<D>::InputStreamOptions() const
    {
        winrt::Windows::Storage::Streams::InputStreamOptions value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->get_InputStreamOptions(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataReader<D>::InputStreamOptions(winrt::Windows::Storage::Streams::InputStreamOptions const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->put_InputStreamOptions(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Storage_Streams_IDataReader<D>::ReadByte() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadByte(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataReader<D>::ReadBytes(array_view<uint8_t> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadBytes(value.size(), put_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Storage_Streams_IDataReader<D>::ReadBuffer(uint32_t length) const
    {
        void* buffer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadBuffer(length, &buffer));
        return winrt::Windows::Storage::Streams::IBuffer{ buffer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Streams_IDataReader<D>::ReadBoolean() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadBoolean(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_Storage_Streams_IDataReader<D>::ReadGuid() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadGuid(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int16_t) consume_Windows_Storage_Streams_IDataReader<D>::ReadInt16() const
    {
        int16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadInt16(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Storage_Streams_IDataReader<D>::ReadInt32() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadInt32(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int64_t) consume_Windows_Storage_Streams_IDataReader<D>::ReadInt64() const
    {
        int64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadInt64(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Storage_Streams_IDataReader<D>::ReadUInt16() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadUInt16(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_Streams_IDataReader<D>::ReadUInt32() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadUInt32(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_Streams_IDataReader<D>::ReadUInt64() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadUInt64(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_Storage_Streams_IDataReader<D>::ReadSingle() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadSingle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Storage_Streams_IDataReader<D>::ReadDouble() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadDouble(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Storage_Streams_IDataReader<D>::ReadString(uint32_t codeUnitCount) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadString(codeUnitCount, &value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Storage_Streams_IDataReader<D>::ReadDateTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadDateTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Storage_Streams_IDataReader<D>::ReadTimeSpan() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->ReadTimeSpan(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReaderLoadOperation) consume_Windows_Storage_Streams_IDataReader<D>::LoadAsync(uint32_t count) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->LoadAsync(count, &operation));
        return winrt::Windows::Storage::Streams::DataReaderLoadOperation{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Storage_Streams_IDataReader<D>::DetachBuffer() const
    {
        void* buffer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->DetachBuffer(&buffer));
        return winrt::Windows::Storage::Streams::IBuffer{ buffer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Storage_Streams_IDataReader<D>::DetachStream() const
    {
        void* stream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReader)->DetachStream(&stream));
        return winrt::Windows::Storage::Streams::IInputStream{ stream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReader) consume_Windows_Storage_Streams_IDataReaderFactory<D>::CreateDataReader(winrt::Windows::Storage::Streams::IInputStream const& inputStream) const
    {
        void* dataReader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReaderFactory)->CreateDataReader(*(void**)(&inputStream), &dataReader));
        return winrt::Windows::Storage::Streams::DataReader{ dataReader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReader) consume_Windows_Storage_Streams_IDataReaderStatics<D>::FromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        void* dataReader{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataReaderStatics)->FromBuffer(*(void**)(&buffer), &dataReader));
        return winrt::Windows::Storage::Streams::DataReader{ dataReader, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_Streams_IDataWriter<D>::UnstoredBufferLength() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->get_UnstoredBufferLength(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::UnicodeEncoding) consume_Windows_Storage_Streams_IDataWriter<D>::UnicodeEncoding() const
    {
        winrt::Windows::Storage::Streams::UnicodeEncoding value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->get_UnicodeEncoding(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::UnicodeEncoding(winrt::Windows::Storage::Streams::UnicodeEncoding const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->put_UnicodeEncoding(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::ByteOrder) consume_Windows_Storage_Streams_IDataWriter<D>::ByteOrder() const
    {
        winrt::Windows::Storage::Streams::ByteOrder value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->get_ByteOrder(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::ByteOrder(winrt::Windows::Storage::Streams::ByteOrder const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->put_ByteOrder(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteByte(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteByte(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteBytes(array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteBytes(value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteBuffer(*(void**)(&buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer, uint32_t start, uint32_t count) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteBufferRange(*(void**)(&buffer), start, count));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteBoolean(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteBoolean(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteGuid(winrt::guid const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteGuid(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteInt16(int16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteInt16(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteInt32(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteInt32(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteInt64(int64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteInt64(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteUInt16(uint16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteUInt16(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteUInt32(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteUInt32(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteUInt64(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteUInt64(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteSingle(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteSingle(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteDouble(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteDouble(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteDateTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteDateTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IDataWriter<D>::WriteTimeSpan(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteTimeSpan(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_Streams_IDataWriter<D>::WriteString(param::hstring const& value) const
    {
        uint32_t codeUnitCount{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->WriteString(*(void**)(&value), &codeUnitCount));
        return codeUnitCount;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Storage_Streams_IDataWriter<D>::MeasureString(param::hstring const& value) const
    {
        uint32_t codeUnitCount{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->MeasureString(*(void**)(&value), &codeUnitCount));
        return codeUnitCount;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataWriterStoreOperation) consume_Windows_Storage_Streams_IDataWriter<D>::StoreAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->StoreAsync(&operation));
        return winrt::Windows::Storage::Streams::DataWriterStoreOperation{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Storage_Streams_IDataWriter<D>::FlushAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->FlushAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Storage_Streams_IDataWriter<D>::DetachBuffer() const
    {
        void* buffer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->DetachBuffer(&buffer));
        return winrt::Windows::Storage::Streams::IBuffer{ buffer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Storage_Streams_IDataWriter<D>::DetachStream() const
    {
        void* outputStream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriter)->DetachStream(&outputStream));
        return winrt::Windows::Storage::Streams::IOutputStream{ outputStream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataWriter) consume_Windows_Storage_Streams_IDataWriterFactory<D>::CreateDataWriter(winrt::Windows::Storage::Streams::IOutputStream const& outputStream) const
    {
        void* dataWriter{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IDataWriterFactory)->CreateDataWriter(*(void**)(&outputStream), &dataWriter));
        return winrt::Windows::Storage::Streams::DataWriter{ dataWriter, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenAsync(param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenAsync(*(void**)(&filePath), static_cast<int32_t>(accessMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenAsync(param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& sharingOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenWithOptionsAsync(*(void**)(&filePath), static_cast<int32_t>(accessMode), static_cast<uint32_t>(sharingOptions), static_cast<int32_t>(openDisposition), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteAsync(param::hstring const& filePath) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteAsync(*(void**)(&filePath), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteAsync(param::hstring const& filePath, winrt::Windows::Storage::StorageOpenOptions const& openOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteWithOptionsAsync(*(void**)(&filePath), static_cast<uint32_t>(openOptions), static_cast<int32_t>(openDisposition), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenForUserAsync(*(void**)(&user), *(void**)(&filePath), static_cast<int32_t>(accessMode), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& sharingOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenForUserWithOptionsAsync(*(void**)(&user), *(void**)(&filePath), static_cast<int32_t>(accessMode), static_cast<uint32_t>(sharingOptions), static_cast<int32_t>(openDisposition), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteForUserAsync(*(void**)(&user), *(void**)(&filePath), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>::OpenTransactedWriteForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::StorageOpenOptions const& openOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics)->OpenTransactedWriteForUserWithOptionsAsync(*(void**)(&user), *(void**)(&filePath), static_cast<uint32_t>(openOptions), static_cast<int32_t>(openDisposition), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IBuffer, uint32_t>) consume_Windows_Storage_Streams_IInputStream<D>::ReadAsync(winrt::Windows::Storage::Streams::IBuffer const& buffer, uint32_t count, winrt::Windows::Storage::Streams::InputStreamOptions const& options) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IInputStream)->ReadAsync(*(void**)(&buffer), count, static_cast<uint32_t>(options), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IBuffer, uint32_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IInputStream>) consume_Windows_Storage_Streams_IInputStreamReference<D>::OpenSequentialReadAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IInputStreamReference)->OpenSequentialReadAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IInputStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>) consume_Windows_Storage_Streams_IOutputStream<D>::WriteAsync(winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IOutputStream)->WriteAsync(*(void**)(&buffer), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Storage_Streams_IOutputStream<D>::FlushAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IOutputStream)->FlushAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Storage_Streams_IPropertySetSerializer<D>::Serialize(winrt::Windows::Foundation::Collections::IPropertySet const& propertySet) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IPropertySetSerializer)->Serialize(*(void**)(&propertySet), &result));
        return winrt::Windows::Storage::Streams::IBuffer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IPropertySetSerializer<D>::Deserialize(winrt::Windows::Foundation::Collections::IPropertySet const& propertySet, winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IPropertySetSerializer)->Deserialize(*(void**)(&propertySet), *(void**)(&buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_Streams_IRandomAccessStream<D>::Size() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->get_Size(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IRandomAccessStream<D>::Size(uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->put_Size(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Storage_Streams_IRandomAccessStream<D>::GetInputStreamAt(uint64_t position) const
    {
        void* stream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->GetInputStreamAt(position, &stream));
        return winrt::Windows::Storage::Streams::IInputStream{ stream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Storage_Streams_IRandomAccessStream<D>::GetOutputStreamAt(uint64_t position) const
    {
        void* stream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->GetOutputStreamAt(position, &stream));
        return winrt::Windows::Storage::Streams::IOutputStream{ stream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Storage_Streams_IRandomAccessStream<D>::Position() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->get_Position(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Storage_Streams_IRandomAccessStream<D>::Seek(uint64_t position) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->Seek(position));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStream) consume_Windows_Storage_Streams_IRandomAccessStream<D>::CloneStream() const
    {
        void* stream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->CloneStream(&stream));
        return winrt::Windows::Storage::Streams::IRandomAccessStream{ stream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Streams_IRandomAccessStream<D>::CanRead() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->get_CanRead(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Storage_Streams_IRandomAccessStream<D>::CanWrite() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStream)->get_CanWrite(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>) consume_Windows_Storage_Streams_IRandomAccessStreamReference<D>::OpenReadAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStreamReference)->OpenReadAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics<D>::CreateFromFile(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* streamReference{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics)->CreateFromFile(*(void**)(&file), &streamReference));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ streamReference, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics<D>::CreateFromUri(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* streamReference{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics)->CreateFromUri(*(void**)(&uri), &streamReference));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ streamReference, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics<D>::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        void* streamReference{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics)->CreateFromStream(*(void**)(&stream), &streamReference));
        return winrt::Windows::Storage::Streams::RandomAccessStreamReference{ streamReference, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>) consume_Windows_Storage_Streams_IRandomAccessStreamStatics<D>::CopyAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStreamStatics)->CopyAsync(*(void**)(&source), *(void**)(&destination), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>) consume_Windows_Storage_Streams_IRandomAccessStreamStatics<D>::CopyAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination, uint64_t bytesToCopy) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStreamStatics)->CopySizeAsync(*(void**)(&source), *(void**)(&destination), bytesToCopy, &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>) consume_Windows_Storage_Streams_IRandomAccessStreamStatics<D>::CopyAndCloseAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Streams::IRandomAccessStreamStatics)->CopyAndCloseAsync(*(void**)(&source), *(void**)(&destination), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>{ operation, take_ownership_from_abi };
    }
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IBuffer> : produce_base<D, winrt::Windows::Storage::Streams::IBuffer>
    {
        int32_t __stdcall get_Capacity(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Capacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Length(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Length(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IBufferFactory> : produce_base<D, winrt::Windows::Storage::Streams::IBufferFactory>
    {
        int32_t __stdcall Create(uint32_t capacity, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::Buffer>(this->shim().Create(capacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IBufferStatics> : produce_base<D, winrt::Windows::Storage::Streams::IBufferStatics>
    {
        int32_t __stdcall CreateCopyFromMemoryBuffer(void* input, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::Buffer>(this->shim().CreateCopyFromMemoryBuffer(*reinterpret_cast<winrt::Windows::Foundation::IMemoryBuffer const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMemoryBufferOverIBuffer(void* input, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::MemoryBuffer>(this->shim().CreateMemoryBufferOverIBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IContentTypeProvider> : produce_base<D, winrt::Windows::Storage::Streams::IContentTypeProvider>
    {
        int32_t __stdcall get_ContentType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IDataReader> : produce_base<D, winrt::Windows::Storage::Streams::IDataReader>
    {
        int32_t __stdcall get_UnconsumedBufferLength(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UnconsumedBufferLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnicodeEncoding(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::UnicodeEncoding>(this->shim().UnicodeEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UnicodeEncoding(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnicodeEncoding(*reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ByteOrder(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::ByteOrder>(this->shim().ByteOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ByteOrder(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ByteOrder(*reinterpret_cast<winrt::Windows::Storage::Streams::ByteOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InputStreamOptions(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::InputStreamOptions>(this->shim().InputStreamOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InputStreamOptions(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InputStreamOptions(*reinterpret_cast<winrt::Windows::Storage::Streams::InputStreamOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadByte(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ReadByte());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBytes(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReadBytes(array_view<uint8_t>(reinterpret_cast<uint8_t*>(value), reinterpret_cast<uint8_t*>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBuffer(uint32_t length, void** buffer) noexcept final try
        {
            clear_abi(buffer);
            typename D::abi_guard guard(this->shim());
            *buffer = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().ReadBuffer(length));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadBoolean(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ReadBoolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadGuid(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().ReadGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadInt16(int16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int16_t>(this->shim().ReadInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadInt32(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ReadInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadInt64(int64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int64_t>(this->shim().ReadInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadUInt16(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ReadUInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadUInt32(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReadUInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadUInt64(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().ReadUInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadSingle(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().ReadSingle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadDouble(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ReadDouble());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadString(uint32_t codeUnitCount, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ReadString(codeUnitCount));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadDateTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().ReadDateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReadTimeSpan(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().ReadTimeSpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadAsync(uint32_t count, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Storage::Streams::DataReaderLoadOperation>(this->shim().LoadAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DetachBuffer(void** buffer) noexcept final try
        {
            clear_abi(buffer);
            typename D::abi_guard guard(this->shim());
            *buffer = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().DetachBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DetachStream(void** stream) noexcept final try
        {
            clear_abi(stream);
            typename D::abi_guard guard(this->shim());
            *stream = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IDataReaderFactory> : produce_base<D, winrt::Windows::Storage::Streams::IDataReaderFactory>
    {
        int32_t __stdcall CreateDataReader(void* inputStream, void** dataReader) noexcept final try
        {
            clear_abi(dataReader);
            typename D::abi_guard guard(this->shim());
            *dataReader = detach_from<winrt::Windows::Storage::Streams::DataReader>(this->shim().CreateDataReader(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&inputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IDataReaderStatics> : produce_base<D, winrt::Windows::Storage::Streams::IDataReaderStatics>
    {
        int32_t __stdcall FromBuffer(void* buffer, void** dataReader) noexcept final try
        {
            clear_abi(dataReader);
            typename D::abi_guard guard(this->shim());
            *dataReader = detach_from<winrt::Windows::Storage::Streams::DataReader>(this->shim().FromBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IDataWriter> : produce_base<D, winrt::Windows::Storage::Streams::IDataWriter>
    {
        int32_t __stdcall get_UnstoredBufferLength(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().UnstoredBufferLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnicodeEncoding(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::UnicodeEncoding>(this->shim().UnicodeEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UnicodeEncoding(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnicodeEncoding(*reinterpret_cast<winrt::Windows::Storage::Streams::UnicodeEncoding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ByteOrder(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::ByteOrder>(this->shim().ByteOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ByteOrder(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ByteOrder(*reinterpret_cast<winrt::Windows::Storage::Streams::ByteOrder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteByte(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteByte(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBytes(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteBytes(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBuffer(void* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBufferRange(void* buffer, uint32_t start, uint32_t count) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer), start, count);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteBoolean(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteBoolean(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteGuid(winrt::guid value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteGuid(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteInt16(int16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteInt16(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteInt32(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteInt32(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteInt64(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteInt64(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteUInt16(uint16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteUInt16(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteUInt32(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteUInt32(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteUInt64(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteUInt64(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteSingle(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteSingle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteDouble(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteDouble(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteDateTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteDateTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteTimeSpan(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WriteTimeSpan(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall WriteString(void* value, uint32_t* codeUnitCount) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *codeUnitCount = detach_from<uint32_t>(this->shim().WriteString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MeasureString(void* value, uint32_t* codeUnitCount) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *codeUnitCount = detach_from<uint32_t>(this->shim().MeasureString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StoreAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Storage::Streams::DataWriterStoreOperation>(this->shim().StoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FlushAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().FlushAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DetachBuffer(void** buffer) noexcept final try
        {
            clear_abi(buffer);
            typename D::abi_guard guard(this->shim());
            *buffer = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().DetachBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DetachStream(void** outputStream) noexcept final try
        {
            clear_abi(outputStream);
            typename D::abi_guard guard(this->shim());
            *outputStream = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IDataWriterFactory> : produce_base<D, winrt::Windows::Storage::Streams::IDataWriterFactory>
    {
        int32_t __stdcall CreateDataWriter(void* outputStream, void** dataWriter) noexcept final try
        {
            clear_abi(dataWriter);
            typename D::abi_guard guard(this->shim());
            *dataWriter = detach_from<winrt::Windows::Storage::Streams::DataWriter>(this->shim().CreateDataWriter(*reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&outputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics> : produce_base<D, winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics>
    {
        int32_t __stdcall OpenAsync(void* filePath, int32_t accessMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Storage::FileAccessMode const*>(&accessMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenWithOptionsAsync(void* filePath, int32_t accessMode, uint32_t sharingOptions, int32_t openDisposition, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Storage::FileAccessMode const*>(&accessMode), *reinterpret_cast<winrt::Windows::Storage::StorageOpenOptions const*>(&sharingOptions), *reinterpret_cast<winrt::Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenTransactedWriteAsync(void* filePath, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync(*reinterpret_cast<hstring const*>(&filePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenTransactedWriteWithOptionsAsync(void* filePath, uint32_t openOptions, int32_t openDisposition, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync(*reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Storage::StorageOpenOptions const*>(&openOptions), *reinterpret_cast<winrt::Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenForUserAsync(void* user, void* filePath, int32_t accessMode, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Storage::FileAccessMode const*>(&accessMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenForUserWithOptionsAsync(void* user, void* filePath, int32_t accessMode, uint32_t sharingOptions, int32_t openDisposition, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Storage::FileAccessMode const*>(&accessMode), *reinterpret_cast<winrt::Windows::Storage::StorageOpenOptions const*>(&sharingOptions), *reinterpret_cast<winrt::Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenTransactedWriteForUserAsync(void* user, void* filePath, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenTransactedWriteForUserWithOptionsAsync(void* user, void* filePath, uint32_t openOptions, int32_t openDisposition, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteForUserAsync(*reinterpret_cast<winrt::Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&filePath), *reinterpret_cast<winrt::Windows::Storage::StorageOpenOptions const*>(&openOptions), *reinterpret_cast<winrt::Windows::Storage::Streams::FileOpenDisposition const*>(&openDisposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IInputStream> : produce_base<D, winrt::Windows::Storage::Streams::IInputStream>
    {
        int32_t __stdcall ReadAsync(void* buffer, uint32_t count, uint32_t options, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IBuffer, uint32_t>>(this->shim().ReadAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer), count, *reinterpret_cast<winrt::Windows::Storage::Streams::InputStreamOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IInputStreamReference> : produce_base<D, winrt::Windows::Storage::Streams::IInputStreamReference>
    {
        int32_t __stdcall OpenSequentialReadAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IInputStream>>(this->shim().OpenSequentialReadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IOutputStream> : produce_base<D, winrt::Windows::Storage::Streams::IOutputStream>
    {
        int32_t __stdcall WriteAsync(void* buffer, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().WriteAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FlushAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().FlushAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IPropertySetSerializer> : produce_base<D, winrt::Windows::Storage::Streams::IPropertySetSerializer>
    {
        int32_t __stdcall Serialize(void* propertySet, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Serialize(*reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&propertySet)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Deserialize(void* propertySet, void* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Deserialize(*reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&propertySet), *reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IRandomAccessStream> : produce_base<D, winrt::Windows::Storage::Streams::IRandomAccessStream>
    {
        int32_t __stdcall get_Size(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Size(uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Size(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetInputStreamAt(uint64_t position, void** stream) noexcept final try
        {
            clear_abi(stream);
            typename D::abi_guard guard(this->shim());
            *stream = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().GetInputStreamAt(position));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOutputStreamAt(uint64_t position, void** stream) noexcept final try
        {
            clear_abi(stream);
            typename D::abi_guard guard(this->shim());
            *stream = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().GetOutputStreamAt(position));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Seek(uint64_t position) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Seek(position);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CloneStream(void** stream) noexcept final try
        {
            clear_abi(stream);
            typename D::abi_guard guard(this->shim());
            *stream = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStream>(this->shim().CloneStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanRead(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanWrite(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanWrite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IRandomAccessStreamReference> : produce_base<D, winrt::Windows::Storage::Streams::IRandomAccessStreamReference>
    {
        int32_t __stdcall OpenReadAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().OpenReadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics> : produce_base<D, winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>
    {
        int32_t __stdcall CreateFromFile(void* file, void** streamReference) noexcept final try
        {
            clear_abi(streamReference);
            typename D::abi_guard guard(this->shim());
            *streamReference = detach_from<winrt::Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().CreateFromFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromUri(void* uri, void** streamReference) noexcept final try
        {
            clear_abi(streamReference);
            typename D::abi_guard guard(this->shim());
            *streamReference = detach_from<winrt::Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().CreateFromUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStream(void* stream, void** streamReference) noexcept final try
        {
            clear_abi(streamReference);
            typename D::abi_guard guard(this->shim());
            *streamReference = detach_from<winrt::Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().CreateFromStream(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IRandomAccessStreamStatics> : produce_base<D, winrt::Windows::Storage::Streams::IRandomAccessStreamStatics>
    {
        int32_t __stdcall CopyAsync(void* source, void* destination, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().CopyAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&source), *reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopySizeAsync(void* source, void* destination, uint64_t bytesToCopy, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().CopyAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&source), *reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&destination), bytesToCopy));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CopyAndCloseAsync(void* source, void* destination, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().CopyAndCloseAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&source), *reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType> : produce_base<D, winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>
    {
    };
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    constexpr auto operator|(InputStreamOptions const left, InputStreamOptions const right) noexcept
    {
        return static_cast<InputStreamOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(InputStreamOptions& left, InputStreamOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(InputStreamOptions const left, InputStreamOptions const right) noexcept
    {
        return static_cast<InputStreamOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(InputStreamOptions& left, InputStreamOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(InputStreamOptions const value) noexcept
    {
        return static_cast<InputStreamOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(InputStreamOptions const left, InputStreamOptions const right) noexcept
    {
        return static_cast<InputStreamOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(InputStreamOptions& left, InputStreamOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline Buffer::Buffer(uint32_t capacity) :
        Buffer(impl::call_factory<Buffer, IBufferFactory>([&](IBufferFactory const& f) { return f.Create(capacity); }))
    {
    }
    inline auto Buffer::CreateCopyFromMemoryBuffer(winrt::Windows::Foundation::IMemoryBuffer const& input)
    {
        return impl::call_factory<Buffer, IBufferStatics>([&](IBufferStatics const& f) { return f.CreateCopyFromMemoryBuffer(input); });
    }
    inline auto Buffer::CreateMemoryBufferOverIBuffer(winrt::Windows::Storage::Streams::IBuffer const& input)
    {
        return impl::call_factory<Buffer, IBufferStatics>([&](IBufferStatics const& f) { return f.CreateMemoryBufferOverIBuffer(input); });
    }
    inline DataReader::DataReader(winrt::Windows::Storage::Streams::IInputStream const& inputStream) :
        DataReader(impl::call_factory<DataReader, IDataReaderFactory>([&](IDataReaderFactory const& f) { return f.CreateDataReader(inputStream); }))
    {
    }
    inline auto DataReader::FromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer)
    {
        return impl::call_factory<DataReader, IDataReaderStatics>([&](IDataReaderStatics const& f) { return f.FromBuffer(buffer); });
    }
    inline DataWriter::DataWriter() :
        DataWriter(impl::call_factory_cast<DataWriter(*)(winrt::Windows::Foundation::IActivationFactory const&), DataWriter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DataWriter>(); }))
    {
    }
    inline DataWriter::DataWriter(winrt::Windows::Storage::Streams::IOutputStream const& outputStream) :
        DataWriter(impl::call_factory<DataWriter, IDataWriterFactory>([&](IDataWriterFactory const& f) { return f.CreateDataWriter(outputStream); }))
    {
    }
    inline auto FileRandomAccessStream::OpenAsync(param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenAsync(filePath, accessMode); });
    }
    inline auto FileRandomAccessStream::OpenAsync(param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& sharingOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenAsync(filePath, accessMode, sharingOptions, openDisposition); });
    }
    inline auto FileRandomAccessStream::OpenTransactedWriteAsync(param::hstring const& filePath)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenTransactedWriteAsync(filePath); });
    }
    inline auto FileRandomAccessStream::OpenTransactedWriteAsync(param::hstring const& filePath, winrt::Windows::Storage::StorageOpenOptions const& openOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenTransactedWriteAsync(filePath, openOptions, openDisposition); });
    }
    inline auto FileRandomAccessStream::OpenForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenForUserAsync(user, filePath, accessMode); });
    }
    inline auto FileRandomAccessStream::OpenForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& sharingOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenForUserAsync(user, filePath, accessMode, sharingOptions, openDisposition); });
    }
    inline auto FileRandomAccessStream::OpenTransactedWriteForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenTransactedWriteForUserAsync(user, filePath); });
    }
    inline auto FileRandomAccessStream::OpenTransactedWriteForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::StorageOpenOptions const& openOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition)
    {
        return impl::call_factory<FileRandomAccessStream, IFileRandomAccessStreamStatics>([&](IFileRandomAccessStreamStatics const& f) { return f.OpenTransactedWriteForUserAsync(user, filePath, openOptions, openDisposition); });
    }
    inline InMemoryRandomAccessStream::InMemoryRandomAccessStream() :
        InMemoryRandomAccessStream(impl::call_factory_cast<InMemoryRandomAccessStream(*)(winrt::Windows::Foundation::IActivationFactory const&), InMemoryRandomAccessStream>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<InMemoryRandomAccessStream>(); }))
    {
    }
    inline auto RandomAccessStream::CopyAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination)
    {
        return impl::call_factory<RandomAccessStream, IRandomAccessStreamStatics>([&](IRandomAccessStreamStatics const& f) { return f.CopyAsync(source, destination); });
    }
    inline auto RandomAccessStream::CopyAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination, uint64_t bytesToCopy)
    {
        return impl::call_factory<RandomAccessStream, IRandomAccessStreamStatics>([&](IRandomAccessStreamStatics const& f) { return f.CopyAsync(source, destination, bytesToCopy); });
    }
    inline auto RandomAccessStream::CopyAndCloseAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination)
    {
        return impl::call_factory<RandomAccessStream, IRandomAccessStreamStatics>([&](IRandomAccessStreamStatics const& f) { return f.CopyAndCloseAsync(source, destination); });
    }
    inline auto RandomAccessStreamReference::CreateFromFile(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<RandomAccessStreamReference, IRandomAccessStreamReferenceStatics>([&](IRandomAccessStreamReferenceStatics const& f) { return f.CreateFromFile(file); });
    }
    inline auto RandomAccessStreamReference::CreateFromUri(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<RandomAccessStreamReference, IRandomAccessStreamReferenceStatics>([&](IRandomAccessStreamReferenceStatics const& f) { return f.CreateFromUri(uri); });
    }
    inline auto RandomAccessStreamReference::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream)
    {
        return impl::call_factory<RandomAccessStreamReference, IRandomAccessStreamReferenceStatics>([&](IRandomAccessStreamReferenceStatics const& f) { return f.CreateFromStream(stream); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Storage::Streams::IBuffer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IBufferFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IBufferStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IContentTypeProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IDataReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IDataReaderFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IDataReaderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IDataWriter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IDataWriterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IInputStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IInputStreamReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IOutputStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IPropertySetSerializer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::Buffer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::DataReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::DataReaderLoadOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::DataWriter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::DataWriterStoreOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::FileInputStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::FileOutputStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::FileRandomAccessStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::InMemoryRandomAccessStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::InputStreamOverStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::OutputStreamOverStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::RandomAccessStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::RandomAccessStreamOverStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Streams::RandomAccessStreamReference> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
