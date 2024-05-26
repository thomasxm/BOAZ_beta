// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_Http_1_H
#define WINRT_Windows_Web_Http_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"
WINRT_EXPORT namespace winrt::Windows::Web::Http
{
    struct __declspec(empty_bases) IHttpBufferContentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpBufferContentFactory>
    {
        IHttpBufferContentFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpBufferContentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpClient :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpClient>
    {
        IHttpClient(std::nullptr_t = nullptr) noexcept {}
        IHttpClient(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpClient2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpClient2>
    {
        IHttpClient2(std::nullptr_t = nullptr) noexcept {}
        IHttpClient2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpClient3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpClient3>
    {
        IHttpClient3(std::nullptr_t = nullptr) noexcept {}
        IHttpClient3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpClientFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpClientFactory>
    {
        IHttpClientFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpClientFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpContent>,
        impl::require<winrt::Windows::Web::Http::IHttpContent, winrt::Windows::Foundation::IClosable>
    {
        IHttpContent(std::nullptr_t = nullptr) noexcept {}
        IHttpContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpCookie :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpCookie>
    {
        IHttpCookie(std::nullptr_t = nullptr) noexcept {}
        IHttpCookie(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpCookieFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpCookieFactory>
    {
        IHttpCookieFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpCookieFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpCookieManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpCookieManager>
    {
        IHttpCookieManager(std::nullptr_t = nullptr) noexcept {}
        IHttpCookieManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpFormUrlEncodedContentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpFormUrlEncodedContentFactory>
    {
        IHttpFormUrlEncodedContentFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpFormUrlEncodedContentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpGetBufferResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpGetBufferResult>
    {
        IHttpGetBufferResult(std::nullptr_t = nullptr) noexcept {}
        IHttpGetBufferResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpGetInputStreamResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpGetInputStreamResult>
    {
        IHttpGetInputStreamResult(std::nullptr_t = nullptr) noexcept {}
        IHttpGetInputStreamResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpGetStringResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpGetStringResult>
    {
        IHttpGetStringResult(std::nullptr_t = nullptr) noexcept {}
        IHttpGetStringResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpMethod :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpMethod>
    {
        IHttpMethod(std::nullptr_t = nullptr) noexcept {}
        IHttpMethod(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpMethodFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpMethodFactory>
    {
        IHttpMethodFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpMethodFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpMethodStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpMethodStatics>
    {
        IHttpMethodStatics(std::nullptr_t = nullptr) noexcept {}
        IHttpMethodStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpMultipartContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpMultipartContent>
    {
        IHttpMultipartContent(std::nullptr_t = nullptr) noexcept {}
        IHttpMultipartContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpMultipartContentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpMultipartContentFactory>
    {
        IHttpMultipartContentFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpMultipartContentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpMultipartFormDataContent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpMultipartFormDataContent>
    {
        IHttpMultipartFormDataContent(std::nullptr_t = nullptr) noexcept {}
        IHttpMultipartFormDataContent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpMultipartFormDataContentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpMultipartFormDataContentFactory>
    {
        IHttpMultipartFormDataContentFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpMultipartFormDataContentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpRequestMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpRequestMessage>
    {
        IHttpRequestMessage(std::nullptr_t = nullptr) noexcept {}
        IHttpRequestMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpRequestMessage2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpRequestMessage2>
    {
        IHttpRequestMessage2(std::nullptr_t = nullptr) noexcept {}
        IHttpRequestMessage2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpRequestMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpRequestMessageFactory>
    {
        IHttpRequestMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpRequestMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpRequestResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpRequestResult>
    {
        IHttpRequestResult(std::nullptr_t = nullptr) noexcept {}
        IHttpRequestResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpResponseMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpResponseMessage>
    {
        IHttpResponseMessage(std::nullptr_t = nullptr) noexcept {}
        IHttpResponseMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpResponseMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpResponseMessageFactory>
    {
        IHttpResponseMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpResponseMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpStreamContentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpStreamContentFactory>
    {
        IHttpStreamContentFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpStreamContentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpStringContentFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpStringContentFactory>
    {
        IHttpStringContentFactory(std::nullptr_t = nullptr) noexcept {}
        IHttpStringContentFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHttpTransportInformation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHttpTransportInformation>
    {
        IHttpTransportInformation(std::nullptr_t = nullptr) noexcept {}
        IHttpTransportInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
