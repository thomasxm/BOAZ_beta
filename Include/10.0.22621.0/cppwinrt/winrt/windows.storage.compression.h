// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Compression_H
#define WINRT_Windows_Storage_Compression_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Storage.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Storage.Compression.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Storage_Compression_ICompressor<D>::FinishAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Compression::ICompressor)->FinishAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) consume_Windows_Storage_Compression_ICompressor<D>::DetachStream() const
    {
        void* stream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Compression::ICompressor)->DetachStream(&stream));
        return winrt::Windows::Storage::Streams::IOutputStream{ stream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Compression::Compressor) consume_Windows_Storage_Compression_ICompressorFactory<D>::CreateCompressor(winrt::Windows::Storage::Streams::IOutputStream const& underlyingStream) const
    {
        void* createdCompressor{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Compression::ICompressorFactory)->CreateCompressor(*(void**)(&underlyingStream), &createdCompressor));
        return winrt::Windows::Storage::Compression::Compressor{ createdCompressor, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Compression::Compressor) consume_Windows_Storage_Compression_ICompressorFactory<D>::CreateCompressorEx(winrt::Windows::Storage::Streams::IOutputStream const& underlyingStream, winrt::Windows::Storage::Compression::CompressAlgorithm const& algorithm, uint32_t blockSize) const
    {
        void* createdCompressor{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Compression::ICompressorFactory)->CreateCompressorEx(*(void**)(&underlyingStream), static_cast<int32_t>(algorithm), blockSize, &createdCompressor));
        return winrt::Windows::Storage::Compression::Compressor{ createdCompressor, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) consume_Windows_Storage_Compression_IDecompressor<D>::DetachStream() const
    {
        void* stream{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Compression::IDecompressor)->DetachStream(&stream));
        return winrt::Windows::Storage::Streams::IInputStream{ stream, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Compression::Decompressor) consume_Windows_Storage_Compression_IDecompressorFactory<D>::CreateDecompressor(winrt::Windows::Storage::Streams::IInputStream const& underlyingStream) const
    {
        void* createdDecompressor{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Storage::Compression::IDecompressorFactory)->CreateDecompressor(*(void**)(&underlyingStream), &createdDecompressor));
        return winrt::Windows::Storage::Compression::Decompressor{ createdDecompressor, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Compression::ICompressor> : produce_base<D, winrt::Windows::Storage::Compression::ICompressor>
    {
        int32_t __stdcall FinishAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DetachStream(void** stream) noexcept final try
        {
            clear_abi(stream);
            typename D::abi_guard guard(this->shim());
            *stream = detach_from<winrt::Windows::Storage::Streams::IOutputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Compression::ICompressorFactory> : produce_base<D, winrt::Windows::Storage::Compression::ICompressorFactory>
    {
        int32_t __stdcall CreateCompressor(void* underlyingStream, void** createdCompressor) noexcept final try
        {
            clear_abi(createdCompressor);
            typename D::abi_guard guard(this->shim());
            *createdCompressor = detach_from<winrt::Windows::Storage::Compression::Compressor>(this->shim().CreateCompressor(*reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&underlyingStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCompressorEx(void* underlyingStream, int32_t algorithm, uint32_t blockSize, void** createdCompressor) noexcept final try
        {
            clear_abi(createdCompressor);
            typename D::abi_guard guard(this->shim());
            *createdCompressor = detach_from<winrt::Windows::Storage::Compression::Compressor>(this->shim().CreateCompressorEx(*reinterpret_cast<winrt::Windows::Storage::Streams::IOutputStream const*>(&underlyingStream), *reinterpret_cast<winrt::Windows::Storage::Compression::CompressAlgorithm const*>(&algorithm), blockSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Compression::IDecompressor> : produce_base<D, winrt::Windows::Storage::Compression::IDecompressor>
    {
        int32_t __stdcall DetachStream(void** stream) noexcept final try
        {
            clear_abi(stream);
            typename D::abi_guard guard(this->shim());
            *stream = detach_from<winrt::Windows::Storage::Streams::IInputStream>(this->shim().DetachStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Storage::Compression::IDecompressorFactory> : produce_base<D, winrt::Windows::Storage::Compression::IDecompressorFactory>
    {
        int32_t __stdcall CreateDecompressor(void* underlyingStream, void** createdDecompressor) noexcept final try
        {
            clear_abi(createdDecompressor);
            typename D::abi_guard guard(this->shim());
            *createdDecompressor = detach_from<winrt::Windows::Storage::Compression::Decompressor>(this->shim().CreateDecompressor(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&underlyingStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Storage::Compression
{
    inline Compressor::Compressor(winrt::Windows::Storage::Streams::IOutputStream const& underlyingStream) :
        Compressor(impl::call_factory<Compressor, ICompressorFactory>([&](ICompressorFactory const& f) { return f.CreateCompressor(underlyingStream); }))
    {
    }
    inline Compressor::Compressor(winrt::Windows::Storage::Streams::IOutputStream const& underlyingStream, winrt::Windows::Storage::Compression::CompressAlgorithm const& algorithm, uint32_t blockSize) :
        Compressor(impl::call_factory<Compressor, ICompressorFactory>([&](ICompressorFactory const& f) { return f.CreateCompressorEx(underlyingStream, algorithm, blockSize); }))
    {
    }
    inline Decompressor::Decompressor(winrt::Windows::Storage::Streams::IInputStream const& underlyingStream) :
        Decompressor(impl::call_factory<Decompressor, IDecompressorFactory>([&](IDecompressorFactory const& f) { return f.CreateDecompressor(underlyingStream); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Storage::Compression::ICompressor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Compression::ICompressorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Compression::IDecompressor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Compression::IDecompressorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Compression::Compressor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Storage::Compression::Decompressor> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
