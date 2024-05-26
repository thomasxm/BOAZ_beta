// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Streams_0_H
#define WINRT_Windows_Storage_Streams_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename TResult, typename TProgress> struct __declspec(empty_bases) IAsyncOperationWithProgress;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct IMemoryBuffer;
    struct MemoryBuffer;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    struct IPropertySet;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    enum class FileAccessMode : int32_t;
    struct IStorageFile;
    enum class StorageOpenOptions : uint32_t;
    struct StorageStreamTransaction;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct User;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    enum class ByteOrder : int32_t
    {
        LittleEndian = 0,
        BigEndian = 1,
    };
    enum class FileOpenDisposition : int32_t
    {
        OpenExisting = 0,
        OpenAlways = 1,
        CreateNew = 2,
        CreateAlways = 3,
        TruncateExisting = 4,
    };
    enum class InputStreamOptions : uint32_t
    {
        None = 0,
        Partial = 0x1,
        ReadAhead = 0x2,
    };
    enum class UnicodeEncoding : int32_t
    {
        Utf8 = 0,
        Utf16LE = 1,
        Utf16BE = 2,
    };
    struct IBuffer;
    struct IBufferFactory;
    struct IBufferStatics;
    struct IContentTypeProvider;
    struct IDataReader;
    struct IDataReaderFactory;
    struct IDataReaderStatics;
    struct IDataWriter;
    struct IDataWriterFactory;
    struct IFileRandomAccessStreamStatics;
    struct IInputStream;
    struct IInputStreamReference;
    struct IOutputStream;
    struct IPropertySetSerializer;
    struct IRandomAccessStream;
    struct IRandomAccessStreamReference;
    struct IRandomAccessStreamReferenceStatics;
    struct IRandomAccessStreamStatics;
    struct IRandomAccessStreamWithContentType;
    struct Buffer;
    struct DataReader;
    struct DataReaderLoadOperation;
    struct DataWriter;
    struct DataWriterStoreOperation;
    struct FileInputStream;
    struct FileOutputStream;
    struct FileRandomAccessStream;
    struct InMemoryRandomAccessStream;
    struct InputStreamOverStream;
    struct OutputStreamOverStream;
    struct RandomAccessStream;
    struct RandomAccessStreamOverStream;
    struct RandomAccessStreamReference;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Storage::Streams::IBuffer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IBufferFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IBufferStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IContentTypeProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IDataReader>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IDataReaderFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IDataReaderStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IDataWriter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IDataWriterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IInputStream>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IInputStreamReference>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IOutputStream>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IPropertySetSerializer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IRandomAccessStream>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Storage::Streams::Buffer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::DataReader>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::DataReaderLoadOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::DataWriter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::DataWriterStoreOperation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::FileInputStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::FileOutputStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::FileRandomAccessStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::InMemoryRandomAccessStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::InputStreamOverStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::OutputStreamOverStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::RandomAccessStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::RandomAccessStreamOverStream>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ using type = class_category; };
    template <> struct category<winrt::Windows::Storage::Streams::ByteOrder>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Streams::FileOpenDisposition>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Streams::InputStreamOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Storage::Streams::UnicodeEncoding>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::Buffer> = L"Windows.Storage.Streams.Buffer";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::DataReader> = L"Windows.Storage.Streams.DataReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::DataReaderLoadOperation> = L"Windows.Storage.Streams.DataReaderLoadOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::DataWriter> = L"Windows.Storage.Streams.DataWriter";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::DataWriterStoreOperation> = L"Windows.Storage.Streams.DataWriterStoreOperation";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::FileInputStream> = L"Windows.Storage.Streams.FileInputStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::FileOutputStream> = L"Windows.Storage.Streams.FileOutputStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::FileRandomAccessStream> = L"Windows.Storage.Streams.FileRandomAccessStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::InMemoryRandomAccessStream> = L"Windows.Storage.Streams.InMemoryRandomAccessStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::InputStreamOverStream> = L"Windows.Storage.Streams.InputStreamOverStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::OutputStreamOverStream> = L"Windows.Storage.Streams.OutputStreamOverStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::RandomAccessStream> = L"Windows.Storage.Streams.RandomAccessStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::RandomAccessStreamOverStream> = L"Windows.Storage.Streams.RandomAccessStreamOverStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::RandomAccessStreamReference> = L"Windows.Storage.Streams.RandomAccessStreamReference";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::ByteOrder> = L"Windows.Storage.Streams.ByteOrder";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::FileOpenDisposition> = L"Windows.Storage.Streams.FileOpenDisposition";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::InputStreamOptions> = L"Windows.Storage.Streams.InputStreamOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::UnicodeEncoding> = L"Windows.Storage.Streams.UnicodeEncoding";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IBuffer> = L"Windows.Storage.Streams.IBuffer";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IBufferFactory> = L"Windows.Storage.Streams.IBufferFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IBufferStatics> = L"Windows.Storage.Streams.IBufferStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IContentTypeProvider> = L"Windows.Storage.Streams.IContentTypeProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IDataReader> = L"Windows.Storage.Streams.IDataReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IDataReaderFactory> = L"Windows.Storage.Streams.IDataReaderFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IDataReaderStatics> = L"Windows.Storage.Streams.IDataReaderStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IDataWriter> = L"Windows.Storage.Streams.IDataWriter";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IDataWriterFactory> = L"Windows.Storage.Streams.IDataWriterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics> = L"Windows.Storage.Streams.IFileRandomAccessStreamStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IInputStream> = L"Windows.Storage.Streams.IInputStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IInputStreamReference> = L"Windows.Storage.Streams.IInputStreamReference";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IOutputStream> = L"Windows.Storage.Streams.IOutputStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IPropertySetSerializer> = L"Windows.Storage.Streams.IPropertySetSerializer";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IRandomAccessStream> = L"Windows.Storage.Streams.IRandomAccessStream";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IRandomAccessStreamReference> = L"Windows.Storage.Streams.IRandomAccessStreamReference";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics> = L"Windows.Storage.Streams.IRandomAccessStreamReferenceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics> = L"Windows.Storage.Streams.IRandomAccessStreamStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType> = L"Windows.Storage.Streams.IRandomAccessStreamWithContentType";
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IBuffer>{ 0x905A0FE0,0xBC53,0x11DF,{ 0x8C,0x49,0x00,0x1E,0x4F,0xC6,0x86,0xDA } }; // 905A0FE0-BC53-11DF-8C49-001E4FC686DA
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IBufferFactory>{ 0x71AF914D,0xC10F,0x484B,{ 0xBC,0x50,0x14,0xBC,0x62,0x3B,0x3A,0x27 } }; // 71AF914D-C10F-484B-BC50-14BC623B3A27
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IBufferStatics>{ 0xE901E65B,0xD716,0x475A,{ 0xA9,0x0A,0xAF,0x72,0x29,0xB1,0xE7,0x41 } }; // E901E65B-D716-475A-A90A-AF7229B1E741
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IContentTypeProvider>{ 0x97D098A5,0x3B99,0x4DE9,{ 0x88,0xA5,0xE1,0x1D,0x2F,0x50,0xC7,0x95 } }; // 97D098A5-3B99-4DE9-88A5-E11D2F50C795
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IDataReader>{ 0xE2B50029,0xB4C1,0x4314,{ 0xA4,0xB8,0xFB,0x81,0x3A,0x2F,0x27,0x5E } }; // E2B50029-B4C1-4314-A4B8-FB813A2F275E
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IDataReaderFactory>{ 0xD7527847,0x57DA,0x4E15,{ 0x91,0x4C,0x06,0x80,0x66,0x99,0xA0,0x98 } }; // D7527847-57DA-4E15-914C-06806699A098
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IDataReaderStatics>{ 0x11FCBFC8,0xF93A,0x471B,{ 0xB1,0x21,0xF3,0x79,0xE3,0x49,0x31,0x3C } }; // 11FCBFC8-F93A-471B-B121-F379E349313C
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IDataWriter>{ 0x64B89265,0xD341,0x4922,{ 0xB3,0x8A,0xDD,0x4A,0xF8,0x80,0x8C,0x4E } }; // 64B89265-D341-4922-B38A-DD4AF8808C4E
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IDataWriterFactory>{ 0x338C67C2,0x8B84,0x4C2B,{ 0x9C,0x50,0x7B,0x87,0x67,0x84,0x7A,0x1F } }; // 338C67C2-8B84-4C2B-9C50-7B8767847A1F
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics>{ 0x73550107,0x3B57,0x4B5D,{ 0x83,0x45,0x55,0x4D,0x2F,0xC6,0x21,0xF0 } }; // 73550107-3B57-4B5D-8345-554D2FC621F0
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IInputStream>{ 0x905A0FE2,0xBC53,0x11DF,{ 0x8C,0x49,0x00,0x1E,0x4F,0xC6,0x86,0xDA } }; // 905A0FE2-BC53-11DF-8C49-001E4FC686DA
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IInputStreamReference>{ 0x43929D18,0x5EC9,0x4B5A,{ 0x91,0x9C,0x42,0x05,0xB0,0xC8,0x04,0xB6 } }; // 43929D18-5EC9-4B5A-919C-4205B0C804B6
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IOutputStream>{ 0x905A0FE6,0xBC53,0x11DF,{ 0x8C,0x49,0x00,0x1E,0x4F,0xC6,0x86,0xDA } }; // 905A0FE6-BC53-11DF-8C49-001E4FC686DA
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IPropertySetSerializer>{ 0x6E8EBF1C,0xEF3D,0x4376,{ 0xB2,0x0E,0x5B,0xE6,0x38,0xAE,0xAC,0x77 } }; // 6E8EBF1C-EF3D-4376-B20E-5BE638AEAC77
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IRandomAccessStream>{ 0x905A0FE1,0xBC53,0x11DF,{ 0x8C,0x49,0x00,0x1E,0x4F,0xC6,0x86,0xDA } }; // 905A0FE1-BC53-11DF-8C49-001E4FC686DA
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>{ 0x33EE3134,0x1DD6,0x4E3A,{ 0x80,0x67,0xD1,0xC1,0x62,0xE8,0x64,0x2B } }; // 33EE3134-1DD6-4E3A-8067-D1C162E8642B
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>{ 0x857309DC,0x3FBF,0x4E7D,{ 0x98,0x6F,0xEF,0x3B,0x1A,0x07,0xA9,0x64 } }; // 857309DC-3FBF-4E7D-986F-EF3B1A07A964
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics>{ 0x524CEDCF,0x6E29,0x4CE5,{ 0x95,0x73,0x6B,0x75,0x3D,0xB6,0x6C,0x3A } }; // 524CEDCF-6E29-4CE5-9573-6B753DB66C3A
    template <> inline constexpr guid guid_v<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>{ 0xCC254827,0x4B3D,0x438F,{ 0x92,0x32,0x10,0xC7,0x6B,0xC7,0xE0,0x38 } }; // CC254827-4B3D-438F-9232-10C76BC7E038
    template <> struct default_interface<winrt::Windows::Storage::Streams::Buffer>{ using type = winrt::Windows::Storage::Streams::IBuffer; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::DataReader>{ using type = winrt::Windows::Storage::Streams::IDataReader; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::DataReaderLoadOperation>{ using type = winrt::Windows::Foundation::IAsyncOperation<uint32_t>; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::DataWriter>{ using type = winrt::Windows::Storage::Streams::IDataWriter; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::DataWriterStoreOperation>{ using type = winrt::Windows::Foundation::IAsyncOperation<uint32_t>; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::FileInputStream>{ using type = winrt::Windows::Storage::Streams::IInputStream; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::FileOutputStream>{ using type = winrt::Windows::Storage::Streams::IOutputStream; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::FileRandomAccessStream>{ using type = winrt::Windows::Storage::Streams::IRandomAccessStream; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::InMemoryRandomAccessStream>{ using type = winrt::Windows::Storage::Streams::IRandomAccessStream; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::InputStreamOverStream>{ using type = winrt::Windows::Storage::Streams::IInputStream; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::OutputStreamOverStream>{ using type = winrt::Windows::Storage::Streams::IOutputStream; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::RandomAccessStreamOverStream>{ using type = winrt::Windows::Storage::Streams::IRandomAccessStream; };
    template <> struct default_interface<winrt::Windows::Storage::Streams::RandomAccessStreamReference>{ using type = winrt::Windows::Storage::Streams::IRandomAccessStreamReference; };
    template <> struct abi<winrt::Windows::Storage::Streams::IBuffer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Capacity(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Length(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Length(uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IBufferFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IBufferStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateCopyFromMemoryBuffer(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateMemoryBufferOverIBuffer(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IContentTypeProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContentType(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IDataReader>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UnconsumedBufferLength(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UnicodeEncoding(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_UnicodeEncoding(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ByteOrder(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ByteOrder(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_InputStreamOptions(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_InputStreamOptions(uint32_t) noexcept = 0;
            virtual int32_t __stdcall ReadByte(uint8_t*) noexcept = 0;
            virtual int32_t __stdcall ReadBytes(uint32_t, uint8_t*) noexcept = 0;
            virtual int32_t __stdcall ReadBuffer(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ReadBoolean(bool*) noexcept = 0;
            virtual int32_t __stdcall ReadGuid(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall ReadInt16(int16_t*) noexcept = 0;
            virtual int32_t __stdcall ReadInt32(int32_t*) noexcept = 0;
            virtual int32_t __stdcall ReadInt64(int64_t*) noexcept = 0;
            virtual int32_t __stdcall ReadUInt16(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall ReadUInt32(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall ReadUInt64(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall ReadSingle(float*) noexcept = 0;
            virtual int32_t __stdcall ReadDouble(double*) noexcept = 0;
            virtual int32_t __stdcall ReadString(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ReadDateTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall ReadTimeSpan(int64_t*) noexcept = 0;
            virtual int32_t __stdcall LoadAsync(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall DetachBuffer(void**) noexcept = 0;
            virtual int32_t __stdcall DetachStream(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IDataReaderFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateDataReader(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IDataReaderStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromBuffer(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IDataWriter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UnstoredBufferLength(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UnicodeEncoding(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_UnicodeEncoding(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ByteOrder(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ByteOrder(int32_t) noexcept = 0;
            virtual int32_t __stdcall WriteByte(uint8_t) noexcept = 0;
            virtual int32_t __stdcall WriteBytes(uint32_t, uint8_t*) noexcept = 0;
            virtual int32_t __stdcall WriteBuffer(void*) noexcept = 0;
            virtual int32_t __stdcall WriteBufferRange(void*, uint32_t, uint32_t) noexcept = 0;
            virtual int32_t __stdcall WriteBoolean(bool) noexcept = 0;
            virtual int32_t __stdcall WriteGuid(winrt::guid) noexcept = 0;
            virtual int32_t __stdcall WriteInt16(int16_t) noexcept = 0;
            virtual int32_t __stdcall WriteInt32(int32_t) noexcept = 0;
            virtual int32_t __stdcall WriteInt64(int64_t) noexcept = 0;
            virtual int32_t __stdcall WriteUInt16(uint16_t) noexcept = 0;
            virtual int32_t __stdcall WriteUInt32(uint32_t) noexcept = 0;
            virtual int32_t __stdcall WriteUInt64(uint64_t) noexcept = 0;
            virtual int32_t __stdcall WriteSingle(float) noexcept = 0;
            virtual int32_t __stdcall WriteDouble(double) noexcept = 0;
            virtual int32_t __stdcall WriteDateTime(int64_t) noexcept = 0;
            virtual int32_t __stdcall WriteTimeSpan(int64_t) noexcept = 0;
            virtual int32_t __stdcall WriteString(void*, uint32_t*) noexcept = 0;
            virtual int32_t __stdcall MeasureString(void*, uint32_t*) noexcept = 0;
            virtual int32_t __stdcall StoreAsync(void**) noexcept = 0;
            virtual int32_t __stdcall FlushAsync(void**) noexcept = 0;
            virtual int32_t __stdcall DetachBuffer(void**) noexcept = 0;
            virtual int32_t __stdcall DetachStream(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IDataWriterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateDataWriter(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall OpenAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall OpenWithOptionsAsync(void*, int32_t, uint32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall OpenTransactedWriteAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall OpenTransactedWriteWithOptionsAsync(void*, uint32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall OpenForUserAsync(void*, void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall OpenForUserWithOptionsAsync(void*, void*, int32_t, uint32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall OpenTransactedWriteForUserAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall OpenTransactedWriteForUserWithOptionsAsync(void*, void*, uint32_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IInputStream>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ReadAsync(void*, uint32_t, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IInputStreamReference>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall OpenSequentialReadAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IOutputStream>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall WriteAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FlushAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IPropertySetSerializer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Serialize(void*, void**) noexcept = 0;
            virtual int32_t __stdcall Deserialize(void*, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IRandomAccessStream>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Size(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall put_Size(uint64_t) noexcept = 0;
            virtual int32_t __stdcall GetInputStreamAt(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetOutputStreamAt(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall get_Position(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall Seek(uint64_t) noexcept = 0;
            virtual int32_t __stdcall CloneStream(void**) noexcept = 0;
            virtual int32_t __stdcall get_CanRead(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CanWrite(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall OpenReadAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFromFile(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFromUri(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateFromStream(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CopyAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CopySizeAsync(void*, void*, uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall CopyAndCloseAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IBuffer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Capacity() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Length() const;
        WINRT_IMPL_AUTO(void) Length(uint32_t value) const;

        auto data() const
        {
            uint8_t* data{};
            static_cast<D const&>(*this).template as<IBufferByteAccess>()->Buffer(&data);
            return data;
        }
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IBuffer>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IBuffer<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IBufferFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::Buffer) Create(uint32_t capacity) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IBufferFactory>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IBufferFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IBufferStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::Buffer) CreateCopyFromMemoryBuffer(winrt::Windows::Foundation::IMemoryBuffer const& input) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::MemoryBuffer) CreateMemoryBufferOverIBuffer(winrt::Windows::Storage::Streams::IBuffer const& input) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IBufferStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IBufferStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IContentTypeProvider
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ContentType() const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IContentTypeProvider>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IContentTypeProvider<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IDataReader
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UnconsumedBufferLength() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::UnicodeEncoding) UnicodeEncoding() const;
        WINRT_IMPL_AUTO(void) UnicodeEncoding(winrt::Windows::Storage::Streams::UnicodeEncoding const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::ByteOrder) ByteOrder() const;
        WINRT_IMPL_AUTO(void) ByteOrder(winrt::Windows::Storage::Streams::ByteOrder const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::InputStreamOptions) InputStreamOptions() const;
        WINRT_IMPL_AUTO(void) InputStreamOptions(winrt::Windows::Storage::Streams::InputStreamOptions const& value) const;
        WINRT_IMPL_AUTO(uint8_t) ReadByte() const;
        WINRT_IMPL_AUTO(void) ReadBytes(array_view<uint8_t> value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) ReadBuffer(uint32_t length) const;
        WINRT_IMPL_AUTO(bool) ReadBoolean() const;
        WINRT_IMPL_AUTO(winrt::guid) ReadGuid() const;
        WINRT_IMPL_AUTO(int16_t) ReadInt16() const;
        WINRT_IMPL_AUTO(int32_t) ReadInt32() const;
        WINRT_IMPL_AUTO(int64_t) ReadInt64() const;
        WINRT_IMPL_AUTO(uint16_t) ReadUInt16() const;
        WINRT_IMPL_AUTO(uint32_t) ReadUInt32() const;
        WINRT_IMPL_AUTO(uint64_t) ReadUInt64() const;
        WINRT_IMPL_AUTO(float) ReadSingle() const;
        WINRT_IMPL_AUTO(double) ReadDouble() const;
        WINRT_IMPL_AUTO(hstring) ReadString(uint32_t codeUnitCount) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) ReadDateTime() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) ReadTimeSpan() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReaderLoadOperation) LoadAsync(uint32_t count) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) DetachBuffer() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) DetachStream() const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IDataReader>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IDataReader<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IDataReaderFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReader) CreateDataReader(winrt::Windows::Storage::Streams::IInputStream const& inputStream) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IDataReaderFactory>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IDataReaderFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IDataReaderStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataReader) FromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IDataReaderStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IDataReaderStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IDataWriter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UnstoredBufferLength() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::UnicodeEncoding) UnicodeEncoding() const;
        WINRT_IMPL_AUTO(void) UnicodeEncoding(winrt::Windows::Storage::Streams::UnicodeEncoding const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::ByteOrder) ByteOrder() const;
        WINRT_IMPL_AUTO(void) ByteOrder(winrt::Windows::Storage::Streams::ByteOrder const& value) const;
        WINRT_IMPL_AUTO(void) WriteByte(uint8_t value) const;
        WINRT_IMPL_AUTO(void) WriteBytes(array_view<uint8_t const> value) const;
        WINRT_IMPL_AUTO(void) WriteBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer) const;
        WINRT_IMPL_AUTO(void) WriteBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer, uint32_t start, uint32_t count) const;
        WINRT_IMPL_AUTO(void) WriteBoolean(bool value) const;
        WINRT_IMPL_AUTO(void) WriteGuid(winrt::guid const& value) const;
        WINRT_IMPL_AUTO(void) WriteInt16(int16_t value) const;
        WINRT_IMPL_AUTO(void) WriteInt32(int32_t value) const;
        WINRT_IMPL_AUTO(void) WriteInt64(int64_t value) const;
        WINRT_IMPL_AUTO(void) WriteUInt16(uint16_t value) const;
        WINRT_IMPL_AUTO(void) WriteUInt32(uint32_t value) const;
        WINRT_IMPL_AUTO(void) WriteUInt64(uint64_t value) const;
        WINRT_IMPL_AUTO(void) WriteSingle(float value) const;
        WINRT_IMPL_AUTO(void) WriteDouble(double value) const;
        WINRT_IMPL_AUTO(void) WriteDateTime(winrt::Windows::Foundation::DateTime const& value) const;
        WINRT_IMPL_AUTO(void) WriteTimeSpan(winrt::Windows::Foundation::TimeSpan const& value) const;
        WINRT_IMPL_AUTO(uint32_t) WriteString(param::hstring const& value) const;
        WINRT_IMPL_AUTO(uint32_t) MeasureString(param::hstring const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataWriterStoreOperation) StoreAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) FlushAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) DetachBuffer() const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) DetachStream() const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IDataWriter>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IDataWriter<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IDataWriterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::DataWriter) CreateDataWriter(winrt::Windows::Storage::Streams::IOutputStream const& outputStream) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IDataWriterFactory>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IDataWriterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) OpenAsync(param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) OpenAsync(param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& sharingOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) OpenTransactedWriteAsync(param::hstring const& filePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) OpenTransactedWriteAsync(param::hstring const& filePath, winrt::Windows::Storage::StorageOpenOptions const& openOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) OpenForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStream>) OpenForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::FileAccessMode const& accessMode, winrt::Windows::Storage::StorageOpenOptions const& sharingOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) OpenTransactedWriteForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::StorageStreamTransaction>) OpenTransactedWriteForUserAsync(winrt::Windows::System::User const& user, param::hstring const& filePath, winrt::Windows::Storage::StorageOpenOptions const& openOptions, winrt::Windows::Storage::Streams::FileOpenDisposition const& openDisposition) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IFileRandomAccessStreamStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IFileRandomAccessStreamStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IInputStream
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Storage::Streams::IBuffer, uint32_t>) ReadAsync(winrt::Windows::Storage::Streams::IBuffer const& buffer, uint32_t count, winrt::Windows::Storage::Streams::InputStreamOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IInputStream>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IInputStream<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IInputStreamReference
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IInputStream>) OpenSequentialReadAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IInputStreamReference>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IInputStreamReference<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IOutputStream
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>) WriteAsync(winrt::Windows::Storage::Streams::IBuffer const& buffer) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) FlushAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IOutputStream>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IOutputStream<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IPropertySetSerializer
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Serialize(winrt::Windows::Foundation::Collections::IPropertySet const& propertySet) const;
        WINRT_IMPL_AUTO(void) Deserialize(winrt::Windows::Foundation::Collections::IPropertySet const& propertySet, winrt::Windows::Storage::Streams::IBuffer const& buffer) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IPropertySetSerializer>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IPropertySetSerializer<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IRandomAccessStream
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) Size() const;
        WINRT_IMPL_AUTO(void) Size(uint64_t value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) GetInputStreamAt(uint64_t position) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) GetOutputStreamAt(uint64_t position) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) Position() const;
        WINRT_IMPL_AUTO(void) Seek(uint64_t position) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStream) CloneStream() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanRead() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanWrite() const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IRandomAccessStream>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IRandomAccessStream<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IRandomAccessStreamReference
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>) OpenReadAsync() const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IRandomAccessStreamReference<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) CreateFromFile(winrt::Windows::Storage::IStorageFile const& file) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) CreateFromUri(winrt::Windows::Foundation::Uri const& uri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::RandomAccessStreamReference) CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IRandomAccessStreamReferenceStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IRandomAccessStreamReferenceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IRandomAccessStreamStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>) CopyAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>) CopyAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination, uint64_t bytesToCopy) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>) CopyAndCloseAsync(winrt::Windows::Storage::Streams::IInputStream const& source, winrt::Windows::Storage::Streams::IOutputStream const& destination) const;
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IRandomAccessStreamStatics>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IRandomAccessStreamStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Storage_Streams_IRandomAccessStreamWithContentType
    {
    };
    template <> struct consume<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>
    {
        template <typename D> using type = consume_Windows_Storage_Streams_IRandomAccessStreamWithContentType<D>;
    };
}
#endif
