// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Audio_1_H
#define WINRT_Windows_Media_Audio_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Media.Effects.0.h"
#include "winrt/impl/Windows.Media.Audio.0.h"
WINRT_EXPORT namespace winrt::Windows::Media::Audio
{
    struct __declspec(empty_bases) IAudioDeviceInputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioDeviceInputNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioDeviceInputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode, winrt::Windows::Media::Audio::IAudioInputNode>
    {
        IAudioDeviceInputNode(std::nullptr_t = nullptr) noexcept {}
        IAudioDeviceInputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioDeviceOutputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioDeviceOutputNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioDeviceOutputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode>
    {
        IAudioDeviceOutputNode(std::nullptr_t = nullptr) noexcept {}
        IAudioDeviceOutputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioFileInputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioFileInputNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioFileInputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode, winrt::Windows::Media::Audio::IAudioInputNode>
    {
        IAudioFileInputNode(std::nullptr_t = nullptr) noexcept {}
        IAudioFileInputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioFileOutputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioFileOutputNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioFileOutputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode>
    {
        IAudioFileOutputNode(std::nullptr_t = nullptr) noexcept {}
        IAudioFileOutputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioFrameCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioFrameCompletedEventArgs>
    {
        IAudioFrameCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAudioFrameCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioFrameInputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioFrameInputNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioFrameInputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode, winrt::Windows::Media::Audio::IAudioInputNode>
    {
        IAudioFrameInputNode(std::nullptr_t = nullptr) noexcept {}
        IAudioFrameInputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioFrameOutputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioFrameOutputNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioFrameOutputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode>
    {
        IAudioFrameOutputNode(std::nullptr_t = nullptr) noexcept {}
        IAudioFrameOutputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraph :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraph>,
        impl::require<winrt::Windows::Media::Audio::IAudioGraph, winrt::Windows::Foundation::IClosable>
    {
        IAudioGraph(std::nullptr_t = nullptr) noexcept {}
        IAudioGraph(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraph2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraph2>,
        impl::require<winrt::Windows::Media::Audio::IAudioGraph2, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioGraph>
    {
        IAudioGraph2(std::nullptr_t = nullptr) noexcept {}
        IAudioGraph2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IAudioGraph2, IAudioGraph2>::CreateDeviceInputNodeAsync;
        using impl::consume_t<IAudioGraph2, winrt::Windows::Media::Audio::IAudioGraph>::CreateDeviceInputNodeAsync;
        using impl::consume_t<IAudioGraph2, IAudioGraph2>::CreateFileInputNodeAsync;
        using impl::consume_t<IAudioGraph2, winrt::Windows::Media::Audio::IAudioGraph>::CreateFileInputNodeAsync;
        using impl::consume_t<IAudioGraph2, IAudioGraph2>::CreateFrameInputNode;
        using impl::consume_t<IAudioGraph2, winrt::Windows::Media::Audio::IAudioGraph>::CreateFrameInputNode;
        using impl::consume_t<IAudioGraph2, IAudioGraph2>::CreateSubmixNode;
        using impl::consume_t<IAudioGraph2, winrt::Windows::Media::Audio::IAudioGraph>::CreateSubmixNode;
    };
    struct __declspec(empty_bases) IAudioGraph3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraph3>
    {
        IAudioGraph3(std::nullptr_t = nullptr) noexcept {}
        IAudioGraph3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraphConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraphConnection>
    {
        IAudioGraphConnection(std::nullptr_t = nullptr) noexcept {}
        IAudioGraphConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraphSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraphSettings>
    {
        IAudioGraphSettings(std::nullptr_t = nullptr) noexcept {}
        IAudioGraphSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraphSettings2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraphSettings2>
    {
        IAudioGraphSettings2(std::nullptr_t = nullptr) noexcept {}
        IAudioGraphSettings2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraphSettingsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraphSettingsFactory>
    {
        IAudioGraphSettingsFactory(std::nullptr_t = nullptr) noexcept {}
        IAudioGraphSettingsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraphStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraphStatics>
    {
        IAudioGraphStatics(std::nullptr_t = nullptr) noexcept {}
        IAudioGraphStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioGraphUnrecoverableErrorOccurredEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioGraphUnrecoverableErrorOccurredEventArgs>
    {
        IAudioGraphUnrecoverableErrorOccurredEventArgs(std::nullptr_t = nullptr) noexcept {}
        IAudioGraphUnrecoverableErrorOccurredEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioInputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioInputNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioInputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode>
    {
        IAudioInputNode(std::nullptr_t = nullptr) noexcept {}
        IAudioInputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioInputNode2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioInputNode2>,
        impl::require<winrt::Windows::Media::Audio::IAudioInputNode2, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode, winrt::Windows::Media::Audio::IAudioInputNode>
    {
        IAudioInputNode2(std::nullptr_t = nullptr) noexcept {}
        IAudioInputNode2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNode>,
        impl::require<winrt::Windows::Media::Audio::IAudioNode, winrt::Windows::Foundation::IClosable>
    {
        IAudioNode(std::nullptr_t = nullptr) noexcept {}
        IAudioNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitter>
    {
        IAudioNodeEmitter(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitter2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitter2>
    {
        IAudioNodeEmitter2(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitter2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitterConeProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitterConeProperties>
    {
        IAudioNodeEmitterConeProperties(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitterConeProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitterDecayModel :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitterDecayModel>
    {
        IAudioNodeEmitterDecayModel(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitterDecayModel(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitterDecayModelStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitterDecayModelStatics>
    {
        IAudioNodeEmitterDecayModelStatics(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitterDecayModelStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitterFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitterFactory>
    {
        IAudioNodeEmitterFactory(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitterFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitterNaturalDecayModelProperties :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitterNaturalDecayModelProperties>
    {
        IAudioNodeEmitterNaturalDecayModelProperties(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitterNaturalDecayModelProperties(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitterShape :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitterShape>
    {
        IAudioNodeEmitterShape(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitterShape(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeEmitterShapeStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeEmitterShapeStatics>
    {
        IAudioNodeEmitterShapeStatics(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeEmitterShapeStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeListener :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeListener>
    {
        IAudioNodeListener(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioNodeWithListener :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioNodeWithListener>,
        impl::require<winrt::Windows::Media::Audio::IAudioNodeWithListener, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode>
    {
        IAudioNodeWithListener(std::nullptr_t = nullptr) noexcept {}
        IAudioNodeWithListener(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioPlaybackConnection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioPlaybackConnection>
    {
        IAudioPlaybackConnection(std::nullptr_t = nullptr) noexcept {}
        IAudioPlaybackConnection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioPlaybackConnectionOpenResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioPlaybackConnectionOpenResult>
    {
        IAudioPlaybackConnectionOpenResult(std::nullptr_t = nullptr) noexcept {}
        IAudioPlaybackConnectionOpenResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioPlaybackConnectionStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioPlaybackConnectionStatics>
    {
        IAudioPlaybackConnectionStatics(std::nullptr_t = nullptr) noexcept {}
        IAudioPlaybackConnectionStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioStateMonitor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioStateMonitor>
    {
        IAudioStateMonitor(std::nullptr_t = nullptr) noexcept {}
        IAudioStateMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IAudioStateMonitorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IAudioStateMonitorStatics>
    {
        IAudioStateMonitorStatics(std::nullptr_t = nullptr) noexcept {}
        IAudioStateMonitorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioDeviceInputNodeResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioDeviceInputNodeResult>
    {
        ICreateAudioDeviceInputNodeResult(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioDeviceInputNodeResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioDeviceInputNodeResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioDeviceInputNodeResult2>
    {
        ICreateAudioDeviceInputNodeResult2(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioDeviceInputNodeResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioDeviceOutputNodeResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioDeviceOutputNodeResult>
    {
        ICreateAudioDeviceOutputNodeResult(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioDeviceOutputNodeResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioDeviceOutputNodeResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioDeviceOutputNodeResult2>
    {
        ICreateAudioDeviceOutputNodeResult2(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioDeviceOutputNodeResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioFileInputNodeResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioFileInputNodeResult>
    {
        ICreateAudioFileInputNodeResult(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioFileInputNodeResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioFileInputNodeResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioFileInputNodeResult2>
    {
        ICreateAudioFileInputNodeResult2(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioFileInputNodeResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioFileOutputNodeResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioFileOutputNodeResult>
    {
        ICreateAudioFileOutputNodeResult(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioFileOutputNodeResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioFileOutputNodeResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioFileOutputNodeResult2>
    {
        ICreateAudioFileOutputNodeResult2(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioFileOutputNodeResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioGraphResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioGraphResult>
    {
        ICreateAudioGraphResult(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioGraphResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateAudioGraphResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateAudioGraphResult2>
    {
        ICreateAudioGraphResult2(std::nullptr_t = nullptr) noexcept {}
        ICreateAudioGraphResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateMediaSourceAudioInputNodeResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateMediaSourceAudioInputNodeResult>
    {
        ICreateMediaSourceAudioInputNodeResult(std::nullptr_t = nullptr) noexcept {}
        ICreateMediaSourceAudioInputNodeResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICreateMediaSourceAudioInputNodeResult2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICreateMediaSourceAudioInputNodeResult2>
    {
        ICreateMediaSourceAudioInputNodeResult2(std::nullptr_t = nullptr) noexcept {}
        ICreateMediaSourceAudioInputNodeResult2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEchoEffectDefinition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEchoEffectDefinition>,
        impl::require<winrt::Windows::Media::Audio::IEchoEffectDefinition, winrt::Windows::Media::Effects::IAudioEffectDefinition>
    {
        IEchoEffectDefinition(std::nullptr_t = nullptr) noexcept {}
        IEchoEffectDefinition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEchoEffectDefinitionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEchoEffectDefinitionFactory>
    {
        IEchoEffectDefinitionFactory(std::nullptr_t = nullptr) noexcept {}
        IEchoEffectDefinitionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEqualizerBand :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEqualizerBand>
    {
        IEqualizerBand(std::nullptr_t = nullptr) noexcept {}
        IEqualizerBand(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEqualizerEffectDefinition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEqualizerEffectDefinition>,
        impl::require<winrt::Windows::Media::Audio::IEqualizerEffectDefinition, winrt::Windows::Media::Effects::IAudioEffectDefinition>
    {
        IEqualizerEffectDefinition(std::nullptr_t = nullptr) noexcept {}
        IEqualizerEffectDefinition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IEqualizerEffectDefinitionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IEqualizerEffectDefinitionFactory>
    {
        IEqualizerEffectDefinitionFactory(std::nullptr_t = nullptr) noexcept {}
        IEqualizerEffectDefinitionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFrameInputNodeQuantumStartedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFrameInputNodeQuantumStartedEventArgs>
    {
        IFrameInputNodeQuantumStartedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IFrameInputNodeQuantumStartedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILimiterEffectDefinition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILimiterEffectDefinition>,
        impl::require<winrt::Windows::Media::Audio::ILimiterEffectDefinition, winrt::Windows::Media::Effects::IAudioEffectDefinition>
    {
        ILimiterEffectDefinition(std::nullptr_t = nullptr) noexcept {}
        ILimiterEffectDefinition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILimiterEffectDefinitionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILimiterEffectDefinitionFactory>
    {
        ILimiterEffectDefinitionFactory(std::nullptr_t = nullptr) noexcept {}
        ILimiterEffectDefinitionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMediaSourceAudioInputNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMediaSourceAudioInputNode>,
        impl::require<winrt::Windows::Media::Audio::IMediaSourceAudioInputNode, winrt::Windows::Foundation::IClosable, winrt::Windows::Media::Audio::IAudioNode, winrt::Windows::Media::Audio::IAudioInputNode, winrt::Windows::Media::Audio::IAudioInputNode2>
    {
        IMediaSourceAudioInputNode(std::nullptr_t = nullptr) noexcept {}
        IMediaSourceAudioInputNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IReverbEffectDefinition :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IReverbEffectDefinition>,
        impl::require<winrt::Windows::Media::Audio::IReverbEffectDefinition, winrt::Windows::Media::Effects::IAudioEffectDefinition>
    {
        IReverbEffectDefinition(std::nullptr_t = nullptr) noexcept {}
        IReverbEffectDefinition(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IReverbEffectDefinitionFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IReverbEffectDefinitionFactory>
    {
        IReverbEffectDefinitionFactory(std::nullptr_t = nullptr) noexcept {}
        IReverbEffectDefinitionFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISetDefaultSpatialAudioFormatResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISetDefaultSpatialAudioFormatResult>
    {
        ISetDefaultSpatialAudioFormatResult(std::nullptr_t = nullptr) noexcept {}
        ISetDefaultSpatialAudioFormatResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialAudioDeviceConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialAudioDeviceConfiguration>
    {
        ISpatialAudioDeviceConfiguration(std::nullptr_t = nullptr) noexcept {}
        ISpatialAudioDeviceConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialAudioDeviceConfigurationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialAudioDeviceConfigurationStatics>
    {
        ISpatialAudioDeviceConfigurationStatics(std::nullptr_t = nullptr) noexcept {}
        ISpatialAudioDeviceConfigurationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialAudioFormatConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialAudioFormatConfiguration>
    {
        ISpatialAudioFormatConfiguration(std::nullptr_t = nullptr) noexcept {}
        ISpatialAudioFormatConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialAudioFormatConfigurationStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialAudioFormatConfigurationStatics>
    {
        ISpatialAudioFormatConfigurationStatics(std::nullptr_t = nullptr) noexcept {}
        ISpatialAudioFormatConfigurationStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialAudioFormatSubtypeStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialAudioFormatSubtypeStatics>
    {
        ISpatialAudioFormatSubtypeStatics(std::nullptr_t = nullptr) noexcept {}
        ISpatialAudioFormatSubtypeStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ISpatialAudioFormatSubtypeStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ISpatialAudioFormatSubtypeStatics2>
    {
        ISpatialAudioFormatSubtypeStatics2(std::nullptr_t = nullptr) noexcept {}
        ISpatialAudioFormatSubtypeStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
