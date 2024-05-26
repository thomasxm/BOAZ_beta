// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_SpeechRecognition_2_H
#define WINRT_Windows_Media_SpeechRecognition_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Globalization.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Media.SpeechRecognition.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::SpeechRecognition
{
    struct __declspec(empty_bases) SpeechContinuousRecognitionCompletedEventArgs : winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs
    {
        SpeechContinuousRecognitionCompletedEventArgs(std::nullptr_t) noexcept {}
        SpeechContinuousRecognitionCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionCompletedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechContinuousRecognitionResultGeneratedEventArgs : winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs
    {
        SpeechContinuousRecognitionResultGeneratedEventArgs(std::nullptr_t) noexcept {}
        SpeechContinuousRecognitionResultGeneratedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionResultGeneratedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechContinuousRecognitionSession : winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession
    {
        SpeechContinuousRecognitionSession(std::nullptr_t) noexcept {}
        SpeechContinuousRecognitionSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechContinuousRecognitionSession(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognitionCompilationResult : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult
    {
        SpeechRecognitionCompilationResult(std::nullptr_t) noexcept {}
        SpeechRecognitionCompilationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionCompilationResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognitionGrammarFileConstraint : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint
    {
        SpeechRecognitionGrammarFileConstraint(std::nullptr_t) noexcept {}
        SpeechRecognitionGrammarFileConstraint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionGrammarFileConstraint(ptr, take_ownership_from_abi) {}
        explicit SpeechRecognitionGrammarFileConstraint(winrt::Windows::Storage::StorageFile const& file);
        SpeechRecognitionGrammarFileConstraint(winrt::Windows::Storage::StorageFile const& file, param::hstring const& tag);
    };
    struct __declspec(empty_bases) SpeechRecognitionHypothesis : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis
    {
        SpeechRecognitionHypothesis(std::nullptr_t) noexcept {}
        SpeechRecognitionHypothesis(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesis(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognitionHypothesisGeneratedEventArgs : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs
    {
        SpeechRecognitionHypothesisGeneratedEventArgs(std::nullptr_t) noexcept {}
        SpeechRecognitionHypothesisGeneratedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionHypothesisGeneratedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognitionListConstraint : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint
    {
        SpeechRecognitionListConstraint(std::nullptr_t) noexcept {}
        SpeechRecognitionListConstraint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionListConstraint(ptr, take_ownership_from_abi) {}
        explicit SpeechRecognitionListConstraint(param::iterable<hstring> const& commands);
        SpeechRecognitionListConstraint(param::iterable<hstring> const& commands, param::hstring const& tag);
    };
    struct __declspec(empty_bases) SpeechRecognitionQualityDegradingEventArgs : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs
    {
        SpeechRecognitionQualityDegradingEventArgs(std::nullptr_t) noexcept {}
        SpeechRecognitionQualityDegradingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionQualityDegradingEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognitionResult : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult,
        impl::require<SpeechRecognitionResult, winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult2>
    {
        SpeechRecognitionResult(std::nullptr_t) noexcept {}
        SpeechRecognitionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognitionSemanticInterpretation : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation
    {
        SpeechRecognitionSemanticInterpretation(std::nullptr_t) noexcept {}
        SpeechRecognitionSemanticInterpretation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionSemanticInterpretation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognitionTopicConstraint : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint
    {
        SpeechRecognitionTopicConstraint(std::nullptr_t) noexcept {}
        SpeechRecognitionTopicConstraint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionTopicConstraint(ptr, take_ownership_from_abi) {}
        SpeechRecognitionTopicConstraint(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint);
        SpeechRecognitionTopicConstraint(winrt::Windows::Media::SpeechRecognition::SpeechRecognitionScenario const& scenario, param::hstring const& topicHint, param::hstring const& tag);
    };
    struct __declspec(empty_bases) SpeechRecognitionVoiceCommandDefinitionConstraint : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint
    {
        SpeechRecognitionVoiceCommandDefinitionConstraint(std::nullptr_t) noexcept {}
        SpeechRecognitionVoiceCommandDefinitionConstraint(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognitionVoiceCommandDefinitionConstraint(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognizer : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer,
        impl::require<SpeechRecognizer, winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer2>
    {
        SpeechRecognizer(std::nullptr_t) noexcept {}
        SpeechRecognizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizer(ptr, take_ownership_from_abi) {}
        SpeechRecognizer();
        explicit SpeechRecognizer(winrt::Windows::Globalization::Language const& language);
        [[nodiscard]] static auto SystemSpeechLanguage();
        [[nodiscard]] static auto SupportedTopicLanguages();
        [[nodiscard]] static auto SupportedGrammarLanguages();
        static auto TrySetSystemSpeechLanguageAsync(winrt::Windows::Globalization::Language const& speechLanguage);
    };
    struct __declspec(empty_bases) SpeechRecognizerStateChangedEventArgs : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs
    {
        SpeechRecognizerStateChangedEventArgs(std::nullptr_t) noexcept {}
        SpeechRecognizerStateChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerStateChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognizerTimeouts : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts
    {
        SpeechRecognizerTimeouts(std::nullptr_t) noexcept {}
        SpeechRecognizerTimeouts(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerTimeouts(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) SpeechRecognizerUIOptions : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions
    {
        SpeechRecognizerUIOptions(std::nullptr_t) noexcept {}
        SpeechRecognizerUIOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::ISpeechRecognizerUIOptions(ptr, take_ownership_from_abi) {}
    };
    struct VoiceCommandManager
    {
        VoiceCommandManager() = delete;
        static auto InstallCommandSetsFromStorageFileAsync(winrt::Windows::Storage::StorageFile const& file);
        [[nodiscard]] static auto InstalledCommandSets();
    };
    struct __declspec(empty_bases) VoiceCommandSet : winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet
    {
        VoiceCommandSet(std::nullptr_t) noexcept {}
        VoiceCommandSet(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::SpeechRecognition::IVoiceCommandSet(ptr, take_ownership_from_abi) {}
    };
}
#endif
