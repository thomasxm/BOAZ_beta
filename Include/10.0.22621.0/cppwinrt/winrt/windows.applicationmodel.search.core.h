// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Search_Core_H
#define WINRT_Windows_ApplicationModel_Search_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Search.h"
#include "winrt/impl/Windows.ApplicationModel.Search.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Search.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionKind) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Kind() const
    {
        winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Tag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::DetailText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_DetailText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Image() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Image(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::ImageAlternateText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_ImageAlternateText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->get_SearchHistoryEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->put_SearchHistoryEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryContext() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->get_SearchHistoryContext(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryContext(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->put_SearchHistoryContext(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetLocalContentSuggestionSettings(winrt::Windows::ApplicationModel::Search::LocalContentSuggestionSettings const& settings) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetLocalContentSuggestionSettings(*(void**)(&settings)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetQuery(param::hstring const& queryText) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetQuery(*(void**)(&queryText)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetQuery(param::hstring const& queryText, param::hstring const& language) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetQueryWithLanguage(*(void**)(&queryText), *(void**)(&language)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetQuery(param::hstring const& queryText, param::hstring const& language, winrt::Windows::ApplicationModel::Search::SearchQueryLinguisticDetails const& linguisticDetails) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetQueryWithSearchQueryLinguisticDetails(*(void**)(&queryText), *(void**)(&language), *(void**)(&linguisticDetails)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestion>) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::Suggestions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->get_Suggestions(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestion>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::AddToHistory(param::hstring const& queryText) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->AddToHistory(*(void**)(&queryText)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::AddToHistory(param::hstring const& queryText, param::hstring const& language) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->AddToHistoryWithLanguage(*(void**)(&queryText), *(void**)(&language)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::ClearHistory() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->ClearHistory());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager, winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->add_SuggestionsRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested_revoker consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager, winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SuggestionsRequested_revoker>(this, SuggestionsRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->remove_SuggestionsRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager, winrt::Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->add_RequestingFocusOnKeyboardInput(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput_revoker consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager, winrt::Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, RequestingFocusOnKeyboardInput_revoker>(this, RequestingFocusOnKeyboardInput(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->remove_RequestingFocusOnKeyboardInput(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::QueryText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_QueryText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Search::SearchQueryLinguisticDetails) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::LinguisticDetails() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_LinguisticDetails(&value));
        return winrt::Windows::ApplicationModel::Search::SearchQueryLinguisticDetails{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Search::SearchSuggestionsRequest) consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::ApplicationModel::Search::SearchSuggestionsRequest{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Search::Core::IRequestingFocusOnKeyboardInputEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Search::Core::IRequestingFocusOnKeyboardInputEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion> : produce_base<D, winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tag(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DetailText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DetailText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Image(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ImageAlternateText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ImageAlternateText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager> : produce_base<D, winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager>
    {
        int32_t __stdcall get_SearchHistoryEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SearchHistoryEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SearchHistoryEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SearchHistoryEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SearchHistoryContext(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SearchHistoryContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SearchHistoryContext(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SearchHistoryContext(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetLocalContentSuggestionSettings(void* settings) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetLocalContentSuggestionSettings(*reinterpret_cast<winrt::Windows::ApplicationModel::Search::LocalContentSuggestionSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetQuery(void* queryText) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetQuery(*reinterpret_cast<hstring const*>(&queryText));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetQueryWithLanguage(void* queryText, void* language) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetQuery(*reinterpret_cast<hstring const*>(&queryText), *reinterpret_cast<hstring const*>(&language));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetQueryWithSearchQueryLinguisticDetails(void* queryText, void* language, void* linguisticDetails) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetQuery(*reinterpret_cast<hstring const*>(&queryText), *reinterpret_cast<hstring const*>(&language), *reinterpret_cast<winrt::Windows::ApplicationModel::Search::SearchQueryLinguisticDetails const*>(&linguisticDetails));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Suggestions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestion>>(this->shim().Suggestions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToHistory(void* queryText) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToHistory(*reinterpret_cast<hstring const*>(&queryText));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToHistoryWithLanguage(void* queryText, void* language) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToHistory(*reinterpret_cast<hstring const*>(&queryText), *reinterpret_cast<hstring const*>(&language));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ClearHistory() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ClearHistory();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SuggestionsRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SuggestionsRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager, winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SuggestionsRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuggestionsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_RequestingFocusOnKeyboardInput(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().RequestingFocusOnKeyboardInput(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager, winrt::Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RequestingFocusOnKeyboardInput(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RequestingFocusOnKeyboardInput(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs> : produce_base<D, winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs>
    {
        int32_t __stdcall get_QueryText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().QueryText());
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
        int32_t __stdcall get_LinguisticDetails(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Search::SearchQueryLinguisticDetails>(this->shim().LinguisticDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Search::SearchSuggestionsRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search::Core
{
    inline SearchSuggestionManager::SearchSuggestionManager() :
        SearchSuggestionManager(impl::call_factory_cast<SearchSuggestionManager(*)(winrt::Windows::Foundation::IActivationFactory const&), SearchSuggestionManager>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SearchSuggestionManager>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::IRequestingFocusOnKeyboardInputEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
