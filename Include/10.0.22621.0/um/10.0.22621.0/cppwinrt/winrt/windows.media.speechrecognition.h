// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_SpeechRecognition_H
#define WINRT_Windows_Media_SpeechRecognition_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Media.SpeechRecognition.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionCompletedEventArgs<D>::Status() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionResultGeneratedEventArgs<D>::Result() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs)->get_Result(&value));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::AutoStopSilenceTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->get_AutoStopSilenceTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::AutoStopSilenceTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->put_AutoStopSilenceTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::StartAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->StartAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::StartAsync(winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionMode const& mode) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->StartWithModeAsync(static_cast<int32_t>(mode), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::StopAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->StopAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::CancelAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->CancelAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::PauseAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->PauseAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Resume() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->Resume());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> const& value) const
    {
        winrt::event_token returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->add_Completed(*(void**)(&value), put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed_revoker consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, Completed_revoker>(this, Completed(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::Completed(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->remove_Completed(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> const& value) const
    {
        winrt::event_token returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->add_ResultGenerated(*(void**)(&value), put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated_revoker consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, ResultGenerated_revoker>(this, ResultGenerated(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechContinuousRecognitionSession<D>::ResultGenerated(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession)->remove_ResultGenerated(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionCompilationResult<D>::Status() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Tag() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_Tag(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Tag(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->put_Tag(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Type() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Probability() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->get_Probability(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionConstraint<D>::Probability(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint)->put_Probability(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionGrammarFileConstraint<D>::GrammarFile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint)->get_GrammarFile(&value));
        return winrt::Windows::Storage::StorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionGrammarFileConstraintFactory<D>::Create(winrt::Windows::Storage::StorageFile const& file) const
    {
        void* constraint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory)->Create(*(void**)(&file), &constraint));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint{ constraint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionGrammarFileConstraintFactory<D>::CreateWithTag(winrt::Windows::Storage::StorageFile const& file, param::hstring const& tag) const
    {
        void* constraint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory)->CreateWithTag(*(void**)(&file), *(void**)(&tag), &constraint));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint{ constraint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionHypothesis<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionHypothesisGeneratedEventArgs<D>::Hypothesis() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs)->get_Hypothesis(&value));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<hstring>) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionListConstraint<D>::Commands() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint)->get_Commands(&value));
        return winrt::Windows::Foundation::Collections::IVector<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionListConstraintFactory<D>::Create(param::iterable<hstring> const& commands) const
    {
        void* constraint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory)->Create(*(void**)(&commands), &constraint));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint{ constraint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionListConstraintFactory<D>::CreateWithTag(param::iterable<hstring> const& commands, param::hstring const& tag) const
    {
        void* constraint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory)->CreateWithTag(*(void**)(&commands), *(void**)(&tag), &constraint));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint{ constraint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionQualityDegradingEventArgs<D>::Problem() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs)->get_Problem(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Status() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConfidence) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Confidence() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConfidence value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Confidence(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::SemanticInterpretation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_SemanticInterpretation(&value));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::GetAlternates(uint32_t maxAlternates) const
    {
        void* alternates{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->GetAlternates(maxAlternates, &alternates));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>{ alternates, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::Constraint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_Constraint(&value));
        return winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::RulePath() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_RulePath(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult<D>::RawConfidence() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult)->get_RawConfidence(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult2<D>::PhraseStartTime() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2)->get_PhraseStartTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionResult2<D>::PhraseDuration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2)->get_PhraseDuration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::Collections::IVectorView<hstring>>) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionSemanticInterpretation<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::Collections::IVectorView<hstring>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraint<D>::Scenario() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint)->get_Scenario(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraint<D>::TopicHint() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint)->get_TopicHint(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraintFactory<D>::Create(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint) const
    {
        void* constraint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory)->Create(static_cast<int32_t>(scenario), *(void**)(&topicHint), &constraint));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint{ constraint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint) consume_Windows_Media_SpeechRecognition_ISpeechRecognitionTopicConstraintFactory<D>::CreateWithTag(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint, param::hstring const& tag) const
    {
        void* constraint{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory)->CreateWithTag(static_cast<int32_t>(scenario), *(void**)(&topicHint), *(void**)(&tag), &constraint));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint{ constraint, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Language) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::CurrentLanguage() const
    {
        void* language{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_CurrentLanguage(&language));
        return winrt::Windows::Globalization::Language{ language, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::Constraints() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_Constraints(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::Timeouts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_Timeouts(&value));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::UIOptions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->get_UIOptions(&value));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult>) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::CompileConstraintsAsync() const
    {
        void* asyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->CompileConstraintsAsync(&asyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult>{ asyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognizeAsync() const
    {
        void* asyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->RecognizeAsync(&asyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>{ asyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognizeWithUIAsync() const
    {
        void* asyncOperation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->RecognizeWithUIAsync(&asyncOperation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>{ asyncOperation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> const& speechRecognitionQualityDegradingHandler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->add_RecognitionQualityDegrading(*(void**)(&speechRecognitionQualityDegradingHandler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading_revoker consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> const& speechRecognitionQualityDegradingHandler) const
    {
        return impl::make_event_revoker<D, RecognitionQualityDegrading_revoker>(this, RecognitionQualityDegrading(speechRecognitionQualityDegradingHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::RecognitionQualityDegrading(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->remove_RecognitionQualityDegrading(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> const& stateChangedHandler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->add_StateChanged(*(void**)(&stateChangedHandler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged_revoker consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> const& stateChangedHandler) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(stateChangedHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer<D>::StateChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer)->remove_StateChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::ContinuousRecognitionSession() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2)->get_ContinuousRecognitionSession(&value));
        return winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognizerState) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::State() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognizerState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::StopRecognitionAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2)->StopRecognitionAsync(&value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> const& value) const
    {
        winrt::event_token returnValue{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2)->add_HypothesisGenerated(*(void**)(&value), put_abi(returnValue)));
        return returnValue;
    }
    template <typename D> typename consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated_revoker consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> const& value) const
    {
        return impl::make_event_revoker<D, HypothesisGenerated_revoker>(this, HypothesisGenerated(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizer2<D>::HypothesisGenerated(winrt::event_token const& value) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2)->remove_HypothesisGenerated(impl::bind_in(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognizer) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerFactory<D>::Create(winrt::Windows::Globalization::Language const& language) const
    {
        void* recognizer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerFactory)->Create(*(void**)(&language), &recognizer));
        return winrt::Windows::Media::SpeechRecognition::SpeechRecognizer{ recognizer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechRecognition::SpeechRecognizerState) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStateChangedEventArgs<D>::State() const
    {
        winrt::Windows::Media::SpeechRecognition::SpeechRecognizerState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Globalization::Language) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics<D>::SystemSpeechLanguage() const
    {
        void* language{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics)->get_SystemSpeechLanguage(&language));
        return winrt::Windows::Globalization::Language{ language, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics<D>::SupportedTopicLanguages() const
    {
        void* languages{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics)->get_SupportedTopicLanguages(&languages));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>{ languages, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics<D>::SupportedGrammarLanguages() const
    {
        void* languages{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics)->get_SupportedGrammarLanguages(&languages));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>{ languages, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerStatics2<D>::TrySetSystemSpeechLanguageAsync(winrt::Windows::Globalization::Language const& speechLanguage) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2)->TrySetSystemSpeechLanguageAsync(*(void**)(&speechLanguage), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::InitialSilenceTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->get_InitialSilenceTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::InitialSilenceTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->put_InitialSilenceTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::EndSilenceTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->get_EndSilenceTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::EndSilenceTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->put_EndSilenceTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::BabbleTimeout() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->get_BabbleTimeout(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerTimeouts<D>::BabbleTimeout(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts)->put_BabbleTimeout(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ExampleText() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_ExampleText(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ExampleText(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_ExampleText(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::AudiblePrompt() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_AudiblePrompt(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::AudiblePrompt(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_AudiblePrompt(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::IsReadBackEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_IsReadBackEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::IsReadBackEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_IsReadBackEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ShowConfirmation() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->get_ShowConfirmation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechRecognition_ISpeechRecognizerUIOptions<D>::ShowConfirmation(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions)->put_ShowConfirmation(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_IVoiceCommandManager<D>::InstallCommandSetsFromStorageFileAsync(winrt::Windows::Storage::StorageFile const& file) const
    {
        void* installAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::IVoiceCommandManager)->InstallCommandSetsFromStorageFileAsync(*(void**)(&file), &installAction));
        return winrt::Windows::Foundation::IAsyncAction{ installAction, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Media::SpeechRecognition::VoiceCommandSet>) consume_Windows_Media_SpeechRecognition_IVoiceCommandManager<D>::InstalledCommandSets() const
    {
        void* voiceCommandSets{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::IVoiceCommandManager)->get_InstalledCommandSets(&voiceCommandSets));
        return winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Media::SpeechRecognition::VoiceCommandSet>{ voiceCommandSets, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_IVoiceCommandSet<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechRecognition_IVoiceCommandSet<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_SpeechRecognition_IVoiceCommandSet<D>::SetPhraseListAsync(param::hstring const& phraseListName, param::async_iterable<hstring> const& phraseList) const
    {
        void* updateAction{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet)->SetPhraseListAsync(*(void**)(&phraseListName), *(void**)(&phraseList), &updateAction));
        return winrt::Windows::Foundation::IAsyncAction{ updateAction, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs>
    {
        int32_t __stdcall get_Result(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession>
    {
        int32_t __stdcall get_AutoStopSilenceTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().AutoStopSilenceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoStopSilenceTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoStopSilenceTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartWithModeAsync(int32_t mode, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync(*reinterpret_cast<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CancelAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().CancelAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall PauseAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().PauseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Resume() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Completed(void* value, winrt::event_token* returnValue) noexcept final try
        {
            zero_abi<winrt::event_token>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Completed(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
        int32_t __stdcall add_ResultGenerated(void* value, winrt::event_token* returnValue) noexcept final try
        {
            zero_abi<winrt::event_token>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::event_token>(this->shim().ResultGenerated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession, winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ResultGenerated(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResultGenerated(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
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
        int32_t __stdcall put_Tag(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Tag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Probability(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability>(this->shim().Probability());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Probability(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Probability(*reinterpret_cast<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConstraintProbability const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint>
    {
        int32_t __stdcall get_GrammarFile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFile>(this->shim().GrammarFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory>
    {
        int32_t __stdcall Create(void* file, void** constraint) noexcept final try
        {
            clear_abi(constraint);
            typename D::abi_guard guard(this->shim());
            *constraint = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint>(this->shim().Create(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTag(void* file, void* tag, void** constraint) noexcept final try
        {
            clear_abi(constraint);
            typename D::abi_guard guard(this->shim());
            *constraint = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint>(this->shim().CreateWithTag(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&file), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs>
    {
        int32_t __stdcall get_Hypothesis(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis>(this->shim().Hypothesis());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint>
    {
        int32_t __stdcall get_Commands(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<hstring>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory>
    {
        int32_t __stdcall Create(void* commands, void** constraint) noexcept final try
        {
            clear_abi(constraint);
            typename D::abi_guard guard(this->shim());
            *constraint = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint>(this->shim().Create(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&commands)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTag(void* commands, void* tag, void** constraint) noexcept final try
        {
            clear_abi(constraint);
            typename D::abi_guard guard(this->shim());
            *constraint = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint>(this->shim().CreateWithTag(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&commands), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs>
    {
        int32_t __stdcall get_Problem(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionAudioProblem>(this->shim().Problem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResultStatus>(this->shim().Status());
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
        int32_t __stdcall get_Confidence(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionConfidence>(this->shim().Confidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SemanticInterpretation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation>(this->shim().SemanticInterpretation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAlternates(uint32_t maxAlternates, void** alternates) noexcept final try
        {
            clear_abi(alternates);
            typename D::abi_guard guard(this->shim());
            *alternates = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>>(this->shim().GetAlternates(maxAlternates));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Constraint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>(this->shim().Constraint());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RulePath(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().RulePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RawConfidence(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RawConfidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2>
    {
        int32_t __stdcall get_PhraseStartTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().PhraseStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PhraseDuration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().PhraseDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation>
    {
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint>
    {
        int32_t __stdcall get_Scenario(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario>(this->shim().Scenario());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TopicHint(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().TopicHint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory>
    {
        int32_t __stdcall Create(int32_t scenario, void* topicHint, void** constraint) noexcept final try
        {
            clear_abi(constraint);
            typename D::abi_guard guard(this->shim());
            *constraint = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const*>(&scenario), *reinterpret_cast<hstring const*>(&topicHint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithTag(int32_t scenario, void* topicHint, void* tag, void** constraint) noexcept final try
        {
            clear_abi(constraint);
            typename D::abi_guard guard(this->shim());
            *constraint = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint>(this->shim().CreateWithTag(*reinterpret_cast<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const*>(&scenario), *reinterpret_cast<hstring const*>(&topicHint), *reinterpret_cast<hstring const*>(&tag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer>
    {
        int32_t __stdcall get_CurrentLanguage(void** language) noexcept final try
        {
            clear_abi(language);
            typename D::abi_guard guard(this->shim());
            *language = detach_from<winrt::Windows::Globalization::Language>(this->shim().CurrentLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Constraints(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint>>(this->shim().Constraints());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timeouts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts>(this->shim().Timeouts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UIOptions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions>(this->shim().UIOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CompileConstraintsAsync(void** asyncOperation) noexcept final try
        {
            clear_abi(asyncOperation);
            typename D::abi_guard guard(this->shim());
            *asyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult>>(this->shim().CompileConstraintsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RecognizeAsync(void** asyncOperation) noexcept final try
        {
            clear_abi(asyncOperation);
            typename D::abi_guard guard(this->shim());
            *asyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>>(this->shim().RecognizeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RecognizeWithUIAsync(void** asyncOperation) noexcept final try
        {
            clear_abi(asyncOperation);
            typename D::abi_guard guard(this->shim());
            *asyncOperation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult>>(this->shim().RecognizeWithUIAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_RecognitionQualityDegrading(void* speechRecognitionQualityDegradingHandler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().RecognitionQualityDegrading(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> const*>(&speechRecognitionQualityDegradingHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_RecognitionQualityDegrading(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RecognitionQualityDegrading(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall add_StateChanged(void* stateChangedHandler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> const*>(&stateChangedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2>
    {
        int32_t __stdcall get_ContinuousRecognitionSession(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession>(this->shim().ContinuousRecognitionSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopRecognitionAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopRecognitionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_HypothesisGenerated(void* value, winrt::event_token* returnValue) noexcept final try
        {
            zero_abi<winrt::event_token>(returnValue);
            typename D::abi_guard guard(this->shim());
            *returnValue = detach_from<winrt::event_token>(this->shim().HypothesisGenerated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_HypothesisGenerated(winrt::event_token value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HypothesisGenerated(*reinterpret_cast<winrt::event_token const*>(&value));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerFactory> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerFactory>
    {
        int32_t __stdcall Create(void* language, void** recognizer) noexcept final try
        {
            clear_abi(recognizer);
            typename D::abi_guard guard(this->shim());
            *recognizer = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer>(this->shim().Create(*reinterpret_cast<winrt::Windows::Globalization::Language const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs>
    {
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics>
    {
        int32_t __stdcall get_SystemSpeechLanguage(void** language) noexcept final try
        {
            clear_abi(language);
            typename D::abi_guard guard(this->shim());
            *language = detach_from<winrt::Windows::Globalization::Language>(this->shim().SystemSpeechLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedTopicLanguages(void** languages) noexcept final try
        {
            clear_abi(languages);
            typename D::abi_guard guard(this->shim());
            *languages = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>>(this->shim().SupportedTopicLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedGrammarLanguages(void** languages) noexcept final try
        {
            clear_abi(languages);
            typename D::abi_guard guard(this->shim());
            *languages = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>>(this->shim().SupportedGrammarLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2>
    {
        int32_t __stdcall TrySetSystemSpeechLanguageAsync(void* speechLanguage, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetSystemSpeechLanguageAsync(*reinterpret_cast<winrt::Windows::Globalization::Language const*>(&speechLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts>
    {
        int32_t __stdcall get_InitialSilenceTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().InitialSilenceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_InitialSilenceTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InitialSilenceTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndSilenceTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().EndSilenceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EndSilenceTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndSilenceTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BabbleTimeout(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().BabbleTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BabbleTimeout(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BabbleTimeout(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions> : produce_base<D, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions>
    {
        int32_t __stdcall get_ExampleText(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ExampleText());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ExampleText(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ExampleText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudiblePrompt(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudiblePrompt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudiblePrompt(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudiblePrompt(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReadBackEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadBackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsReadBackEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsReadBackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShowConfirmation(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShowConfirmation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ShowConfirmation(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowConfirmation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::IVoiceCommandManager> : produce_base<D, winrt::Windows::Media::SpeechRecognition::IVoiceCommandManager>
    {
        int32_t __stdcall InstallCommandSetsFromStorageFileAsync(void* file, void** installAction) noexcept final try
        {
            clear_abi(installAction);
            typename D::abi_guard guard(this->shim());
            *installAction = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().InstallCommandSetsFromStorageFileAsync(*reinterpret_cast<winrt::Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstalledCommandSets(void** voiceCommandSets) noexcept final try
        {
            clear_abi(voiceCommandSets);
            typename D::abi_guard guard(this->shim());
            *voiceCommandSets = detach_from<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Media::SpeechRecognition::VoiceCommandSet>>(this->shim().InstalledCommandSets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet> : produce_base<D, winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet>
    {
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
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
        int32_t __stdcall SetPhraseListAsync(void* phraseListName, void* phraseList, void** updateAction) noexcept final try
        {
            clear_abi(updateAction);
            typename D::abi_guard guard(this->shim());
            *updateAction = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetPhraseListAsync(*reinterpret_cast<hstring const*>(&phraseListName), *reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&phraseList)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::SpeechRecognition
{
    inline SpeechRecognitionGrammarFileConstraint::SpeechRecognitionGrammarFileConstraint(winrt::Windows::Storage::StorageFile const& file) :
        SpeechRecognitionGrammarFileConstraint(impl::call_factory<SpeechRecognitionGrammarFileConstraint, ISpeechRecognitionGrammarFileConstraintFactory>([&](ISpeechRecognitionGrammarFileConstraintFactory const& f) { return f.Create(file); }))
    {
    }
    inline SpeechRecognitionGrammarFileConstraint::SpeechRecognitionGrammarFileConstraint(winrt::Windows::Storage::StorageFile const& file, param::hstring const& tag) :
        SpeechRecognitionGrammarFileConstraint(impl::call_factory<SpeechRecognitionGrammarFileConstraint, ISpeechRecognitionGrammarFileConstraintFactory>([&](ISpeechRecognitionGrammarFileConstraintFactory const& f) { return f.CreateWithTag(file, tag); }))
    {
    }
    inline SpeechRecognitionListConstraint::SpeechRecognitionListConstraint(param::iterable<hstring> const& commands) :
        SpeechRecognitionListConstraint(impl::call_factory<SpeechRecognitionListConstraint, ISpeechRecognitionListConstraintFactory>([&](ISpeechRecognitionListConstraintFactory const& f) { return f.Create(commands); }))
    {
    }
    inline SpeechRecognitionListConstraint::SpeechRecognitionListConstraint(param::iterable<hstring> const& commands, param::hstring const& tag) :
        SpeechRecognitionListConstraint(impl::call_factory<SpeechRecognitionListConstraint, ISpeechRecognitionListConstraintFactory>([&](ISpeechRecognitionListConstraintFactory const& f) { return f.CreateWithTag(commands, tag); }))
    {
    }
    inline SpeechRecognitionTopicConstraint::SpeechRecognitionTopicConstraint(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint) :
        SpeechRecognitionTopicConstraint(impl::call_factory<SpeechRecognitionTopicConstraint, ISpeechRecognitionTopicConstraintFactory>([&](ISpeechRecognitionTopicConstraintFactory const& f) { return f.Create(scenario, topicHint); }))
    {
    }
    inline SpeechRecognitionTopicConstraint::SpeechRecognitionTopicConstraint(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint, param::hstring const& tag) :
        SpeechRecognitionTopicConstraint(impl::call_factory<SpeechRecognitionTopicConstraint, ISpeechRecognitionTopicConstraintFactory>([&](ISpeechRecognitionTopicConstraintFactory const& f) { return f.CreateWithTag(scenario, topicHint, tag); }))
    {
    }
    inline SpeechRecognizer::SpeechRecognizer() :
        SpeechRecognizer(impl::call_factory_cast<SpeechRecognizer(*)(winrt::Windows::Foundation::IActivationFactory const&), SpeechRecognizer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SpeechRecognizer>(); }))
    {
    }
    inline SpeechRecognizer::SpeechRecognizer(winrt::Windows::Globalization::Language const& language) :
        SpeechRecognizer(impl::call_factory<SpeechRecognizer, ISpeechRecognizerFactory>([&](ISpeechRecognizerFactory const& f) { return f.Create(language); }))
    {
    }
    inline auto SpeechRecognizer::SystemSpeechLanguage()
    {
        return impl::call_factory_cast<winrt::Windows::Globalization::Language(*)(ISpeechRecognizerStatics const&), SpeechRecognizer, ISpeechRecognizerStatics>([](ISpeechRecognizerStatics const& f) { return f.SystemSpeechLanguage(); });
    }
    inline auto SpeechRecognizer::SupportedTopicLanguages()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>(*)(ISpeechRecognizerStatics const&), SpeechRecognizer, ISpeechRecognizerStatics>([](ISpeechRecognizerStatics const& f) { return f.SupportedTopicLanguages(); });
    }
    inline auto SpeechRecognizer::SupportedGrammarLanguages()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Globalization::Language>(*)(ISpeechRecognizerStatics const&), SpeechRecognizer, ISpeechRecognizerStatics>([](ISpeechRecognizerStatics const& f) { return f.SupportedGrammarLanguages(); });
    }
    inline auto SpeechRecognizer::TrySetSystemSpeechLanguageAsync(winrt::Windows::Globalization::Language const& speechLanguage)
    {
        return impl::call_factory<SpeechRecognizer, ISpeechRecognizerStatics2>([&](ISpeechRecognizerStatics2 const& f) { return f.TrySetSystemSpeechLanguageAsync(speechLanguage); });
    }
    inline auto VoiceCommandManager::InstallCommandSetsFromStorageFileAsync(winrt::Windows::Storage::StorageFile const& file)
    {
        return impl::call_factory<VoiceCommandManager, IVoiceCommandManager>([&](IVoiceCommandManager const& f) { return f.InstallCommandSetsFromStorageFileAsync(file); });
    }
    inline auto VoiceCommandManager::InstalledCommandSets()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IMapView<hstring, winrt::Windows::Media::SpeechRecognition::VoiceCommandSet>(*)(IVoiceCommandManager const&), VoiceCommandManager, IVoiceCommandManager>([](IVoiceCommandManager const& f) { return f.InstalledCommandSets(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraintFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraintFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraintFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::IVoiceCommandManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionResultGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechContinuousRecognitionSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionCompilationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionGrammarFileConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesis> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionHypothesisGeneratedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionListConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionQualityDegradingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionSemanticInterpretation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionTopicConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognitionVoiceCommandDefinitionConstraint> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerTimeouts> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::SpeechRecognizerUIOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::VoiceCommandManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechRecognition::VoiceCommandSet> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
