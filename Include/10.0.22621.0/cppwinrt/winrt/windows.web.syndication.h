// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_Syndication_H
#define WINRT_Windows_Web_Syndication_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Web.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Web.Syndication.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationAttribute<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationAttribute)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationAttribute<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationAttribute)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationAttribute<D>::Namespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationAttribute)->get_Namespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationAttribute<D>::Namespace(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationAttribute)->put_Namespace(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationAttribute<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationAttribute)->get_Value(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationAttribute<D>::Value(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationAttribute)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationAttribute) consume_Windows_Web_Syndication_ISyndicationAttributeFactory<D>::CreateSyndicationAttribute(param::hstring const& attributeName, param::hstring const& attributeNamespace, param::hstring const& attributeValue) const
    {
        void* syndicationAttribute{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationAttributeFactory)->CreateSyndicationAttribute(*(void**)(&attributeName), *(void**)(&attributeNamespace), *(void**)(&attributeValue), &syndicationAttribute));
        return winrt::Windows::Web::Syndication::SyndicationAttribute{ syndicationAttribute, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationCategory<D>::Label() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategory)->get_Label(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationCategory<D>::Label(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategory)->put_Label(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationCategory<D>::Scheme() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategory)->get_Scheme(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationCategory<D>::Scheme(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategory)->put_Scheme(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationCategory<D>::Term() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategory)->get_Term(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationCategory<D>::Term(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategory)->put_Term(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationCategory) consume_Windows_Web_Syndication_ISyndicationCategoryFactory<D>::CreateSyndicationCategory(param::hstring const& term) const
    {
        void* category{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategoryFactory)->CreateSyndicationCategory(*(void**)(&term), &category));
        return winrt::Windows::Web::Syndication::SyndicationCategory{ category, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationCategory) consume_Windows_Web_Syndication_ISyndicationCategoryFactory<D>::CreateSyndicationCategoryEx(param::hstring const& term, param::hstring const& scheme, param::hstring const& label) const
    {
        void* category{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationCategoryFactory)->CreateSyndicationCategoryEx(*(void**)(&term), *(void**)(&scheme), *(void**)(&label), &category));
        return winrt::Windows::Web::Syndication::SyndicationCategory{ category, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Web_Syndication_ISyndicationClient<D>::ServerCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->get_ServerCredential(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationClient<D>::ServerCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->put_ServerCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Security::Credentials::PasswordCredential) consume_Windows_Web_Syndication_ISyndicationClient<D>::ProxyCredential() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->get_ProxyCredential(&value));
        return winrt::Windows::Security::Credentials::PasswordCredential{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationClient<D>::ProxyCredential(winrt::Windows::Security::Credentials::PasswordCredential const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->put_ProxyCredential(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_Syndication_ISyndicationClient<D>::MaxResponseBufferSize() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->get_MaxResponseBufferSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationClient<D>::MaxResponseBufferSize(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->put_MaxResponseBufferSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_Syndication_ISyndicationClient<D>::Timeout() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->get_Timeout(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationClient<D>::Timeout(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->put_Timeout(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Web_Syndication_ISyndicationClient<D>::BypassCacheOnRetrieve() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->get_BypassCacheOnRetrieve(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationClient<D>::BypassCacheOnRetrieve(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->put_BypassCacheOnRetrieve(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationClient<D>::SetRequestHeader(param::hstring const& name, param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->SetRequestHeader(*(void**)(&name), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Web::Syndication::SyndicationFeed, winrt::Windows::Web::Syndication::RetrievalProgress>) consume_Windows_Web_Syndication_ISyndicationClient<D>::RetrieveFeedAsync(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClient)->RetrieveFeedAsync(*(void**)(&uri), &operation));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Web::Syndication::SyndicationFeed, winrt::Windows::Web::Syndication::RetrievalProgress>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationClient) consume_Windows_Web_Syndication_ISyndicationClientFactory<D>::CreateSyndicationClient(winrt::Windows::Security::Credentials::PasswordCredential const& serverCredential) const
    {
        void* syndicationClient{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationClientFactory)->CreateSyndicationClient(*(void**)(&serverCredential), &syndicationClient));
        return winrt::Windows::Web::Syndication::SyndicationClient{ syndicationClient, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationContent<D>::SourceUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationContent)->get_SourceUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationContent<D>::SourceUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationContent)->put_SourceUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationContent) consume_Windows_Web_Syndication_ISyndicationContentFactory<D>::CreateSyndicationContent(param::hstring const& text, winrt::Windows::Web::Syndication::SyndicationTextType const& type) const
    {
        void* content{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationContentFactory)->CreateSyndicationContent(*(void**)(&text), static_cast<int32_t>(type), &content));
        return winrt::Windows::Web::Syndication::SyndicationContent{ content, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationContent) consume_Windows_Web_Syndication_ISyndicationContentFactory<D>::CreateSyndicationContentWithSourceUri(winrt::Windows::Foundation::Uri const& sourceUri) const
    {
        void* content{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationContentFactory)->CreateSyndicationContentWithSourceUri(*(void**)(&sourceUri), &content));
        return winrt::Windows::Web::Syndication::SyndicationContent{ content, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationErrorStatus) consume_Windows_Web_Syndication_ISyndicationErrorStatics<D>::GetStatus(int32_t hresult) const
    {
        winrt::Windows::Web::Syndication::SyndicationErrorStatus status{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationErrorStatics)->GetStatus(hresult, reinterpret_cast<int32_t*>(&status)));
        return status;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Authors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Authors(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationCategory>) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Categories() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Categories(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationCategory>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Contributors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Contributors(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationGenerator) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Generator() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Generator(&value));
        return winrt::Windows::Web::Syndication::SyndicationGenerator{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Generator(winrt::Windows::Web::Syndication::SyndicationGenerator const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_Generator(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationFeed<D>::IconUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_IconUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::IconUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_IconUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationItem>) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Items() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Items(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationItem>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Web_Syndication_ISyndicationFeed<D>::LastUpdatedTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_LastUpdatedTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::LastUpdatedTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_LastUpdatedTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationLink>) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Links() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Links(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationLink>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationFeed<D>::ImageUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_ImageUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::ImageUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_ImageUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Rights() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Rights(&value));
        return winrt::Windows::Web::Syndication::ISyndicationText{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Rights(winrt::Windows::Web::Syndication::ISyndicationText const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_Rights(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Subtitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Subtitle(&value));
        return winrt::Windows::Web::Syndication::ISyndicationText{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Subtitle(winrt::Windows::Web::Syndication::ISyndicationText const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_Subtitle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_Title(&value));
        return winrt::Windows::Web::Syndication::ISyndicationText{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Title(winrt::Windows::Web::Syndication::ISyndicationText const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationFeed<D>::FirstUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_FirstUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationFeed<D>::LastUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_LastUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationFeed<D>::NextUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_NextUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationFeed<D>::PreviousUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_PreviousUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationFormat) consume_Windows_Web_Syndication_ISyndicationFeed<D>::SourceFormat() const
    {
        winrt::Windows::Web::Syndication::SyndicationFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->get_SourceFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::Load(param::hstring const& feed) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->Load(*(void**)(&feed)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationFeed<D>::LoadFromXml(winrt::Windows::Data::Xml::Dom::XmlDocument const& feedDocument) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeed)->LoadFromXml(*(void**)(&feedDocument)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationFeed) consume_Windows_Web_Syndication_ISyndicationFeedFactory<D>::CreateSyndicationFeed(param::hstring const& title, param::hstring const& subtitle, winrt::Windows::Foundation::Uri const& uri) const
    {
        void* feed{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationFeedFactory)->CreateSyndicationFeed(*(void**)(&title), *(void**)(&subtitle), *(void**)(&uri), &feed));
        return winrt::Windows::Web::Syndication::SyndicationFeed{ feed, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationGenerator<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationGenerator)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationGenerator<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationGenerator)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationGenerator<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationGenerator)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationGenerator<D>::Uri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationGenerator)->put_Uri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationGenerator<D>::Version() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationGenerator)->get_Version(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationGenerator<D>::Version(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationGenerator)->put_Version(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationGenerator) consume_Windows_Web_Syndication_ISyndicationGeneratorFactory<D>::CreateSyndicationGenerator(param::hstring const& text) const
    {
        void* generator{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationGeneratorFactory)->CreateSyndicationGenerator(*(void**)(&text), &generator));
        return winrt::Windows::Web::Syndication::SyndicationGenerator{ generator, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>) consume_Windows_Web_Syndication_ISyndicationItem<D>::Authors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Authors(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationCategory>) consume_Windows_Web_Syndication_ISyndicationItem<D>::Categories() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Categories(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationCategory>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>) consume_Windows_Web_Syndication_ISyndicationItem<D>::Contributors() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Contributors(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationContent) consume_Windows_Web_Syndication_ISyndicationItem<D>::Content() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Content(&value));
        return winrt::Windows::Web::Syndication::SyndicationContent{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::Content(winrt::Windows::Web::Syndication::SyndicationContent const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_Content(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationItem<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Web_Syndication_ISyndicationItem<D>::LastUpdatedTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_LastUpdatedTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::LastUpdatedTime(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_LastUpdatedTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationLink>) consume_Windows_Web_Syndication_ISyndicationItem<D>::Links() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Links(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationLink>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Web_Syndication_ISyndicationItem<D>::PublishedDate() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_PublishedDate(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::PublishedDate(winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_PublishedDate(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) consume_Windows_Web_Syndication_ISyndicationItem<D>::Rights() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Rights(&value));
        return winrt::Windows::Web::Syndication::ISyndicationText{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::Rights(winrt::Windows::Web::Syndication::ISyndicationText const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_Rights(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationFeed) consume_Windows_Web_Syndication_ISyndicationItem<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Source(&value));
        return winrt::Windows::Web::Syndication::SyndicationFeed{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::Source(winrt::Windows::Web::Syndication::SyndicationFeed const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_Source(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) consume_Windows_Web_Syndication_ISyndicationItem<D>::Summary() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Summary(&value));
        return winrt::Windows::Web::Syndication::ISyndicationText{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::Summary(winrt::Windows::Web::Syndication::ISyndicationText const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_Summary(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::ISyndicationText) consume_Windows_Web_Syndication_ISyndicationItem<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_Title(&value));
        return winrt::Windows::Web::Syndication::ISyndicationText{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::Title(winrt::Windows::Web::Syndication::ISyndicationText const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationItem<D>::CommentsUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_CommentsUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::CommentsUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->put_CommentsUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationItem<D>::EditUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_EditUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationItem<D>::EditMediaUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_EditMediaUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationItem<D>::ETag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_ETag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationItem<D>::ItemUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->get_ItemUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::Load(param::hstring const& item) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->Load(*(void**)(&item)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationItem<D>::LoadFromXml(winrt::Windows::Data::Xml::Dom::XmlDocument const& itemDocument) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItem)->LoadFromXml(*(void**)(&itemDocument)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationItem) consume_Windows_Web_Syndication_ISyndicationItemFactory<D>::CreateSyndicationItem(param::hstring const& title, winrt::Windows::Web::Syndication::SyndicationContent const& content, winrt::Windows::Foundation::Uri const& uri) const
    {
        void* item{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationItemFactory)->CreateSyndicationItem(*(void**)(&title), *(void**)(&content), *(void**)(&uri), &item));
        return winrt::Windows::Web::Syndication::SyndicationItem{ item, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Web_Syndication_ISyndicationLink<D>::Length() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->get_Length(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationLink<D>::Length(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->put_Length(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationLink<D>::MediaType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->get_MediaType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationLink<D>::MediaType(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->put_MediaType(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationLink<D>::Relationship() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->get_Relationship(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationLink<D>::Relationship(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->put_Relationship(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationLink<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationLink<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationLink<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationLink<D>::Uri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->put_Uri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationLink<D>::ResourceLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->get_ResourceLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationLink<D>::ResourceLanguage(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLink)->put_ResourceLanguage(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationLink) consume_Windows_Web_Syndication_ISyndicationLinkFactory<D>::CreateSyndicationLink(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* link{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLinkFactory)->CreateSyndicationLink(*(void**)(&uri), &link));
        return winrt::Windows::Web::Syndication::SyndicationLink{ link, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationLink) consume_Windows_Web_Syndication_ISyndicationLinkFactory<D>::CreateSyndicationLinkEx(winrt::Windows::Foundation::Uri const& uri, param::hstring const& relationship, param::hstring const& title, param::hstring const& mediaType, uint32_t length) const
    {
        void* link{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationLinkFactory)->CreateSyndicationLinkEx(*(void**)(&uri), *(void**)(&relationship), *(void**)(&title), *(void**)(&mediaType), length, &link));
        return winrt::Windows::Web::Syndication::SyndicationLink{ link, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationNode<D>::NodeName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->get_NodeName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationNode<D>::NodeName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->put_NodeName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationNode<D>::NodeNamespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->get_NodeNamespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationNode<D>::NodeNamespace(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->put_NodeNamespace(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationNode<D>::NodeValue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->get_NodeValue(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationNode<D>::NodeValue(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->put_NodeValue(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationNode<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationNode<D>::Language(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->put_Language(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationNode<D>::BaseUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->get_BaseUri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationNode<D>::BaseUri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->put_BaseUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationAttribute>) consume_Windows_Web_Syndication_ISyndicationNode<D>::AttributeExtensions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->get_AttributeExtensions(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationAttribute>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::ISyndicationNode>) consume_Windows_Web_Syndication_ISyndicationNode<D>::ElementExtensions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->get_ElementExtensions(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::ISyndicationNode>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_Web_Syndication_ISyndicationNode<D>::GetXmlDocument(winrt::Windows::Web::Syndication::SyndicationFormat const& format) const
    {
        void* xmlDocument{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNode)->GetXmlDocument(static_cast<int32_t>(format), &xmlDocument));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ xmlDocument, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationNode) consume_Windows_Web_Syndication_ISyndicationNodeFactory<D>::CreateSyndicationNode(param::hstring const& nodeName, param::hstring const& nodeNamespace, param::hstring const& nodeValue) const
    {
        void* node{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationNodeFactory)->CreateSyndicationNode(*(void**)(&nodeName), *(void**)(&nodeNamespace), *(void**)(&nodeValue), &node));
        return winrt::Windows::Web::Syndication::SyndicationNode{ node, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationPerson<D>::Email() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPerson)->get_Email(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationPerson<D>::Email(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPerson)->put_Email(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationPerson<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPerson)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationPerson<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPerson)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Web_Syndication_ISyndicationPerson<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPerson)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationPerson<D>::Uri(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPerson)->put_Uri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationPerson) consume_Windows_Web_Syndication_ISyndicationPersonFactory<D>::CreateSyndicationPerson(param::hstring const& name) const
    {
        void* person{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPersonFactory)->CreateSyndicationPerson(*(void**)(&name), &person));
        return winrt::Windows::Web::Syndication::SyndicationPerson{ person, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationPerson) consume_Windows_Web_Syndication_ISyndicationPersonFactory<D>::CreateSyndicationPersonEx(param::hstring const& name, param::hstring const& email, winrt::Windows::Foundation::Uri const& uri) const
    {
        void* person{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationPersonFactory)->CreateSyndicationPersonEx(*(void**)(&name), *(void**)(&email), *(void**)(&uri), &person));
        return winrt::Windows::Web::Syndication::SyndicationPerson{ person, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationText<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationText)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationText<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationText)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Web_Syndication_ISyndicationText<D>::Type() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationText)->get_Type(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationText<D>::Type(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationText)->put_Type(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_Web_Syndication_ISyndicationText<D>::Xml() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationText)->get_Xml(&value));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Web_Syndication_ISyndicationText<D>::Xml(winrt::Windows::Data::Xml::Dom::XmlDocument const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationText)->put_Xml(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationText) consume_Windows_Web_Syndication_ISyndicationTextFactory<D>::CreateSyndicationText(param::hstring const& text) const
    {
        void* syndicationText{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationTextFactory)->CreateSyndicationText(*(void**)(&text), &syndicationText));
        return winrt::Windows::Web::Syndication::SyndicationText{ syndicationText, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Web::Syndication::SyndicationText) consume_Windows_Web_Syndication_ISyndicationTextFactory<D>::CreateSyndicationTextEx(param::hstring const& text, winrt::Windows::Web::Syndication::SyndicationTextType const& type) const
    {
        void* syndicationText{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Web::Syndication::ISyndicationTextFactory)->CreateSyndicationTextEx(*(void**)(&text), static_cast<int32_t>(type), &syndicationText));
        return winrt::Windows::Web::Syndication::SyndicationText{ syndicationText, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationAttribute> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationAttribute>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Namespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Namespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Namespace(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Namespace(*reinterpret_cast<hstring const*>(&value));
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
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationAttributeFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationAttributeFactory>
    {
        int32_t __stdcall CreateSyndicationAttribute(void* attributeName, void* attributeNamespace, void* attributeValue, void** syndicationAttribute) noexcept final try
        {
            clear_abi(syndicationAttribute);
            typename D::abi_guard guard(this->shim());
            *syndicationAttribute = detach_from<winrt::Windows::Web::Syndication::SyndicationAttribute>(this->shim().CreateSyndicationAttribute(*reinterpret_cast<hstring const*>(&attributeName), *reinterpret_cast<hstring const*>(&attributeNamespace), *reinterpret_cast<hstring const*>(&attributeValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationCategory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationCategory>
    {
        int32_t __stdcall get_Label(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Label(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Scheme(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Scheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Scheme(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Scheme(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Term(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Term());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Term(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Term(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationCategoryFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationCategoryFactory>
    {
        int32_t __stdcall CreateSyndicationCategory(void* term, void** category) noexcept final try
        {
            clear_abi(category);
            typename D::abi_guard guard(this->shim());
            *category = detach_from<winrt::Windows::Web::Syndication::SyndicationCategory>(this->shim().CreateSyndicationCategory(*reinterpret_cast<hstring const*>(&term)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSyndicationCategoryEx(void* term, void* scheme, void* label, void** category) noexcept final try
        {
            clear_abi(category);
            typename D::abi_guard guard(this->shim());
            *category = detach_from<winrt::Windows::Web::Syndication::SyndicationCategory>(this->shim().CreateSyndicationCategoryEx(*reinterpret_cast<hstring const*>(&term), *reinterpret_cast<hstring const*>(&scheme), *reinterpret_cast<hstring const*>(&label)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationClient> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationClient>
    {
        int32_t __stdcall get_ServerCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().ServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ServerCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ServerCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProxyCredential(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Security::Credentials::PasswordCredential>(this->shim().ProxyCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProxyCredential(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProxyCredential(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxResponseBufferSize(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxResponseBufferSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MaxResponseBufferSize(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxResponseBufferSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timeout(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Timeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Timeout(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Timeout(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BypassCacheOnRetrieve(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().BypassCacheOnRetrieve());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BypassCacheOnRetrieve(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BypassCacheOnRetrieve(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetRequestHeader(void* name, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetRequestHeader(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RetrieveFeedAsync(void* uri, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Web::Syndication::SyndicationFeed, winrt::Windows::Web::Syndication::RetrievalProgress>>(this->shim().RetrieveFeedAsync(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationClientFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationClientFactory>
    {
        int32_t __stdcall CreateSyndicationClient(void* serverCredential, void** syndicationClient) noexcept final try
        {
            clear_abi(syndicationClient);
            typename D::abi_guard guard(this->shim());
            *syndicationClient = detach_from<winrt::Windows::Web::Syndication::SyndicationClient>(this->shim().CreateSyndicationClient(*reinterpret_cast<winrt::Windows::Security::Credentials::PasswordCredential const*>(&serverCredential)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationContent> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationContent>
    {
        int32_t __stdcall get_SourceUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().SourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SourceUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationContentFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationContentFactory>
    {
        int32_t __stdcall CreateSyndicationContent(void* text, int32_t type, void** content) noexcept final try
        {
            clear_abi(content);
            typename D::abi_guard guard(this->shim());
            *content = detach_from<winrt::Windows::Web::Syndication::SyndicationContent>(this->shim().CreateSyndicationContent(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<winrt::Windows::Web::Syndication::SyndicationTextType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSyndicationContentWithSourceUri(void* sourceUri, void** content) noexcept final try
        {
            clear_abi(content);
            typename D::abi_guard guard(this->shim());
            *content = detach_from<winrt::Windows::Web::Syndication::SyndicationContent>(this->shim().CreateSyndicationContentWithSourceUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&sourceUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationErrorStatics> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationErrorStatics>
    {
        int32_t __stdcall GetStatus(int32_t hresult, int32_t* status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *status = detach_from<winrt::Windows::Web::Syndication::SyndicationErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationFeed> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationFeed>
    {
        int32_t __stdcall get_Authors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>>(this->shim().Authors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Categories(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationCategory>>(this->shim().Categories());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Contributors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>>(this->shim().Contributors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Generator(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::SyndicationGenerator>(this->shim().Generator());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Generator(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Generator(*reinterpret_cast<winrt::Windows::Web::Syndication::SyndicationGenerator const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IconUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().IconUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IconUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IconUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Items(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastUpdatedTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastUpdatedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastUpdatedTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastUpdatedTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Links(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationLink>>(this->shim().Links());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ImageUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ImageUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ImageUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImageUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rights(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::ISyndicationText>(this->shim().Rights());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Rights(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rights(*reinterpret_cast<winrt::Windows::Web::Syndication::ISyndicationText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subtitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::ISyndicationText>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Subtitle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Subtitle(*reinterpret_cast<winrt::Windows::Web::Syndication::ISyndicationText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::ISyndicationText>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<winrt::Windows::Web::Syndication::ISyndicationText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FirstUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().FirstUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().LastUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NextUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().NextUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PreviousUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().PreviousUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::SyndicationFormat>(this->shim().SourceFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Load(void* feed) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Load(*reinterpret_cast<hstring const*>(&feed));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadFromXml(void* feedDocument) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoadFromXml(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&feedDocument));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationFeedFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationFeedFactory>
    {
        int32_t __stdcall CreateSyndicationFeed(void* title, void* subtitle, void* uri, void** feed) noexcept final try
        {
            clear_abi(feed);
            typename D::abi_guard guard(this->shim());
            *feed = detach_from<winrt::Windows::Web::Syndication::SyndicationFeed>(this->shim().CreateSyndicationFeed(*reinterpret_cast<hstring const*>(&title), *reinterpret_cast<hstring const*>(&subtitle), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationGenerator> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationGenerator>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Uri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Uri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Version(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Version(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Version(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationGeneratorFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationGeneratorFactory>
    {
        int32_t __stdcall CreateSyndicationGenerator(void* text, void** generator) noexcept final try
        {
            clear_abi(generator);
            typename D::abi_guard guard(this->shim());
            *generator = detach_from<winrt::Windows::Web::Syndication::SyndicationGenerator>(this->shim().CreateSyndicationGenerator(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationItem> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationItem>
    {
        int32_t __stdcall get_Authors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>>(this->shim().Authors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Categories(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationCategory>>(this->shim().Categories());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Contributors(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationPerson>>(this->shim().Contributors());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Content(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::SyndicationContent>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Content(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Content(*reinterpret_cast<winrt::Windows::Web::Syndication::SyndicationContent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LastUpdatedTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().LastUpdatedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LastUpdatedTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LastUpdatedTime(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Links(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationLink>>(this->shim().Links());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PublishedDate(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().PublishedDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PublishedDate(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PublishedDate(*reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rights(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::ISyndicationText>(this->shim().Rights());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Rights(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rights(*reinterpret_cast<winrt::Windows::Web::Syndication::ISyndicationText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::SyndicationFeed>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Source(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Source(*reinterpret_cast<winrt::Windows::Web::Syndication::SyndicationFeed const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Summary(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::ISyndicationText>(this->shim().Summary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Summary(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Summary(*reinterpret_cast<winrt::Windows::Web::Syndication::ISyndicationText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Web::Syndication::ISyndicationText>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<winrt::Windows::Web::Syndication::ISyndicationText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CommentsUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().CommentsUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CommentsUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommentsUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EditUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().EditUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EditMediaUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().EditMediaUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ETag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ETag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().ItemUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Load(void* item) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Load(*reinterpret_cast<hstring const*>(&item));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadFromXml(void* itemDocument) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoadFromXml(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&itemDocument));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationItemFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationItemFactory>
    {
        int32_t __stdcall CreateSyndicationItem(void* title, void* content, void* uri, void** item) noexcept final try
        {
            clear_abi(item);
            typename D::abi_guard guard(this->shim());
            *item = detach_from<winrt::Windows::Web::Syndication::SyndicationItem>(this->shim().CreateSyndicationItem(*reinterpret_cast<hstring const*>(&title), *reinterpret_cast<winrt::Windows::Web::Syndication::SyndicationContent const*>(&content), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationLink> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationLink>
    {
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
        int32_t __stdcall get_MediaType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MediaType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MediaType(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Relationship(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Relationship());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Relationship(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Relationship(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Uri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Uri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResourceLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ResourceLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ResourceLanguage(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResourceLanguage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationLinkFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationLinkFactory>
    {
        int32_t __stdcall CreateSyndicationLink(void* uri, void** link) noexcept final try
        {
            clear_abi(link);
            typename D::abi_guard guard(this->shim());
            *link = detach_from<winrt::Windows::Web::Syndication::SyndicationLink>(this->shim().CreateSyndicationLink(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSyndicationLinkEx(void* uri, void* relationship, void* title, void* mediaType, uint32_t length, void** link) noexcept final try
        {
            clear_abi(link);
            typename D::abi_guard guard(this->shim());
            *link = detach_from<winrt::Windows::Web::Syndication::SyndicationLink>(this->shim().CreateSyndicationLinkEx(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&relationship), *reinterpret_cast<hstring const*>(&title), *reinterpret_cast<hstring const*>(&mediaType), length));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationNode> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationNode>
    {
        int32_t __stdcall get_NodeName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NodeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NodeName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NodeName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NodeNamespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NodeNamespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NodeNamespace(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NodeNamespace(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NodeValue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NodeValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NodeValue(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NodeValue(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Language(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BaseUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().BaseUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BaseUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BaseUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AttributeExtensions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::SyndicationAttribute>>(this->shim().AttributeExtensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ElementExtensions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Web::Syndication::ISyndicationNode>>(this->shim().ElementExtensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetXmlDocument(int32_t format, void** xmlDocument) noexcept final try
        {
            clear_abi(xmlDocument);
            typename D::abi_guard guard(this->shim());
            *xmlDocument = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetXmlDocument(*reinterpret_cast<winrt::Windows::Web::Syndication::SyndicationFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationNodeFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationNodeFactory>
    {
        int32_t __stdcall CreateSyndicationNode(void* nodeName, void* nodeNamespace, void* nodeValue, void** node) noexcept final try
        {
            clear_abi(node);
            typename D::abi_guard guard(this->shim());
            *node = detach_from<winrt::Windows::Web::Syndication::SyndicationNode>(this->shim().CreateSyndicationNode(*reinterpret_cast<hstring const*>(&nodeName), *reinterpret_cast<hstring const*>(&nodeNamespace), *reinterpret_cast<hstring const*>(&nodeValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationPerson> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationPerson>
    {
        int32_t __stdcall get_Email(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Email());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Email(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Email(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Uri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Uri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationPersonFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationPersonFactory>
    {
        int32_t __stdcall CreateSyndicationPerson(void* name, void** person) noexcept final try
        {
            clear_abi(person);
            typename D::abi_guard guard(this->shim());
            *person = detach_from<winrt::Windows::Web::Syndication::SyndicationPerson>(this->shim().CreateSyndicationPerson(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSyndicationPersonEx(void* name, void* email, void* uri, void** person) noexcept final try
        {
            clear_abi(person);
            typename D::abi_guard guard(this->shim());
            *person = detach_from<winrt::Windows::Web::Syndication::SyndicationPerson>(this->shim().CreateSyndicationPersonEx(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&email), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationText> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationText>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Type(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Type(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Xml(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().Xml());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Xml(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Xml(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Web::Syndication::ISyndicationTextFactory> : produce_base<D, winrt::Windows::Web::Syndication::ISyndicationTextFactory>
    {
        int32_t __stdcall CreateSyndicationText(void* text, void** syndicationText) noexcept final try
        {
            clear_abi(syndicationText);
            typename D::abi_guard guard(this->shim());
            *syndicationText = detach_from<winrt::Windows::Web::Syndication::SyndicationText>(this->shim().CreateSyndicationText(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSyndicationTextEx(void* text, int32_t type, void** syndicationText) noexcept final try
        {
            clear_abi(syndicationText);
            typename D::abi_guard guard(this->shim());
            *syndicationText = detach_from<winrt::Windows::Web::Syndication::SyndicationText>(this->shim().CreateSyndicationTextEx(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<winrt::Windows::Web::Syndication::SyndicationTextType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Web::Syndication
{
    inline SyndicationAttribute::SyndicationAttribute() :
        SyndicationAttribute(impl::call_factory_cast<SyndicationAttribute(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationAttribute>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationAttribute>(); }))
    {
    }
    inline SyndicationAttribute::SyndicationAttribute(param::hstring const& attributeName, param::hstring const& attributeNamespace, param::hstring const& attributeValue) :
        SyndicationAttribute(impl::call_factory<SyndicationAttribute, ISyndicationAttributeFactory>([&](ISyndicationAttributeFactory const& f) { return f.CreateSyndicationAttribute(attributeName, attributeNamespace, attributeValue); }))
    {
    }
    inline SyndicationCategory::SyndicationCategory() :
        SyndicationCategory(impl::call_factory_cast<SyndicationCategory(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationCategory>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationCategory>(); }))
    {
    }
    inline SyndicationCategory::SyndicationCategory(param::hstring const& term) :
        SyndicationCategory(impl::call_factory<SyndicationCategory, ISyndicationCategoryFactory>([&](ISyndicationCategoryFactory const& f) { return f.CreateSyndicationCategory(term); }))
    {
    }
    inline SyndicationCategory::SyndicationCategory(param::hstring const& term, param::hstring const& scheme, param::hstring const& label) :
        SyndicationCategory(impl::call_factory<SyndicationCategory, ISyndicationCategoryFactory>([&](ISyndicationCategoryFactory const& f) { return f.CreateSyndicationCategoryEx(term, scheme, label); }))
    {
    }
    inline SyndicationClient::SyndicationClient() :
        SyndicationClient(impl::call_factory_cast<SyndicationClient(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationClient>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationClient>(); }))
    {
    }
    inline SyndicationClient::SyndicationClient(winrt::Windows::Security::Credentials::PasswordCredential const& serverCredential) :
        SyndicationClient(impl::call_factory<SyndicationClient, ISyndicationClientFactory>([&](ISyndicationClientFactory const& f) { return f.CreateSyndicationClient(serverCredential); }))
    {
    }
    inline SyndicationContent::SyndicationContent() :
        SyndicationContent(impl::call_factory_cast<SyndicationContent(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationContent>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationContent>(); }))
    {
    }
    inline SyndicationContent::SyndicationContent(param::hstring const& text, winrt::Windows::Web::Syndication::SyndicationTextType const& type) :
        SyndicationContent(impl::call_factory<SyndicationContent, ISyndicationContentFactory>([&](ISyndicationContentFactory const& f) { return f.CreateSyndicationContent(text, type); }))
    {
    }
    inline SyndicationContent::SyndicationContent(winrt::Windows::Foundation::Uri const& sourceUri) :
        SyndicationContent(impl::call_factory<SyndicationContent, ISyndicationContentFactory>([&](ISyndicationContentFactory const& f) { return f.CreateSyndicationContentWithSourceUri(sourceUri); }))
    {
    }
    inline auto SyndicationError::GetStatus(int32_t hresult)
    {
        return impl::call_factory<SyndicationError, ISyndicationErrorStatics>([&](ISyndicationErrorStatics const& f) { return f.GetStatus(hresult); });
    }
    inline SyndicationFeed::SyndicationFeed() :
        SyndicationFeed(impl::call_factory_cast<SyndicationFeed(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationFeed>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationFeed>(); }))
    {
    }
    inline SyndicationFeed::SyndicationFeed(param::hstring const& title, param::hstring const& subtitle, winrt::Windows::Foundation::Uri const& uri) :
        SyndicationFeed(impl::call_factory<SyndicationFeed, ISyndicationFeedFactory>([&](ISyndicationFeedFactory const& f) { return f.CreateSyndicationFeed(title, subtitle, uri); }))
    {
    }
    inline SyndicationGenerator::SyndicationGenerator() :
        SyndicationGenerator(impl::call_factory_cast<SyndicationGenerator(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationGenerator>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationGenerator>(); }))
    {
    }
    inline SyndicationGenerator::SyndicationGenerator(param::hstring const& text) :
        SyndicationGenerator(impl::call_factory<SyndicationGenerator, ISyndicationGeneratorFactory>([&](ISyndicationGeneratorFactory const& f) { return f.CreateSyndicationGenerator(text); }))
    {
    }
    inline SyndicationItem::SyndicationItem() :
        SyndicationItem(impl::call_factory_cast<SyndicationItem(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationItem>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationItem>(); }))
    {
    }
    inline SyndicationItem::SyndicationItem(param::hstring const& title, winrt::Windows::Web::Syndication::SyndicationContent const& content, winrt::Windows::Foundation::Uri const& uri) :
        SyndicationItem(impl::call_factory<SyndicationItem, ISyndicationItemFactory>([&](ISyndicationItemFactory const& f) { return f.CreateSyndicationItem(title, content, uri); }))
    {
    }
    inline SyndicationLink::SyndicationLink() :
        SyndicationLink(impl::call_factory_cast<SyndicationLink(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationLink>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationLink>(); }))
    {
    }
    inline SyndicationLink::SyndicationLink(winrt::Windows::Foundation::Uri const& uri) :
        SyndicationLink(impl::call_factory<SyndicationLink, ISyndicationLinkFactory>([&](ISyndicationLinkFactory const& f) { return f.CreateSyndicationLink(uri); }))
    {
    }
    inline SyndicationLink::SyndicationLink(winrt::Windows::Foundation::Uri const& uri, param::hstring const& relationship, param::hstring const& title, param::hstring const& mediaType, uint32_t length) :
        SyndicationLink(impl::call_factory<SyndicationLink, ISyndicationLinkFactory>([&](ISyndicationLinkFactory const& f) { return f.CreateSyndicationLinkEx(uri, relationship, title, mediaType, length); }))
    {
    }
    inline SyndicationNode::SyndicationNode() :
        SyndicationNode(impl::call_factory_cast<SyndicationNode(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationNode>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationNode>(); }))
    {
    }
    inline SyndicationNode::SyndicationNode(param::hstring const& nodeName, param::hstring const& nodeNamespace, param::hstring const& nodeValue) :
        SyndicationNode(impl::call_factory<SyndicationNode, ISyndicationNodeFactory>([&](ISyndicationNodeFactory const& f) { return f.CreateSyndicationNode(nodeName, nodeNamespace, nodeValue); }))
    {
    }
    inline SyndicationPerson::SyndicationPerson() :
        SyndicationPerson(impl::call_factory_cast<SyndicationPerson(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationPerson>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationPerson>(); }))
    {
    }
    inline SyndicationPerson::SyndicationPerson(param::hstring const& name) :
        SyndicationPerson(impl::call_factory<SyndicationPerson, ISyndicationPersonFactory>([&](ISyndicationPersonFactory const& f) { return f.CreateSyndicationPerson(name); }))
    {
    }
    inline SyndicationPerson::SyndicationPerson(param::hstring const& name, param::hstring const& email, winrt::Windows::Foundation::Uri const& uri) :
        SyndicationPerson(impl::call_factory<SyndicationPerson, ISyndicationPersonFactory>([&](ISyndicationPersonFactory const& f) { return f.CreateSyndicationPersonEx(name, email, uri); }))
    {
    }
    inline SyndicationText::SyndicationText() :
        SyndicationText(impl::call_factory_cast<SyndicationText(*)(winrt::Windows::Foundation::IActivationFactory const&), SyndicationText>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SyndicationText>(); }))
    {
    }
    inline SyndicationText::SyndicationText(param::hstring const& text) :
        SyndicationText(impl::call_factory<SyndicationText, ISyndicationTextFactory>([&](ISyndicationTextFactory const& f) { return f.CreateSyndicationText(text); }))
    {
    }
    inline SyndicationText::SyndicationText(param::hstring const& text, winrt::Windows::Web::Syndication::SyndicationTextType const& type) :
        SyndicationText(impl::call_factory<SyndicationText, ISyndicationTextFactory>([&](ISyndicationTextFactory const& f) { return f.CreateSyndicationTextEx(text, type); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationAttribute> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationAttributeFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationCategory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationCategoryFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationClient> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationClientFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationContent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationContentFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationErrorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationFeed> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationFeedFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationGenerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationGeneratorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationItemFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationLink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationLinkFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationNodeFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationPerson> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationPersonFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationText> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::ISyndicationTextFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationAttribute> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationCategory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationClient> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationContent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationFeed> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationGenerator> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationItem> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationLink> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationPerson> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Web::Syndication::SyndicationText> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
