// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Midi_1_H
#define WINRT_Windows_Devices_Midi_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Midi.0.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Midi
{
    struct __declspec(empty_bases) IMidiChannelPressureMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiChannelPressureMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiChannelPressureMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiChannelPressureMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiChannelPressureMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiChannelPressureMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiChannelPressureMessageFactory>
    {
        IMidiChannelPressureMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiChannelPressureMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiControlChangeMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiControlChangeMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiControlChangeMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiControlChangeMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiControlChangeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiControlChangeMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiControlChangeMessageFactory>
    {
        IMidiControlChangeMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiControlChangeMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiInPort :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiInPort>,
        impl::require<winrt::Windows::Devices::Midi::IMidiInPort, winrt::Windows::Foundation::IClosable>
    {
        IMidiInPort(std::nullptr_t = nullptr) noexcept {}
        IMidiInPort(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiInPortStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiInPortStatics>
    {
        IMidiInPortStatics(std::nullptr_t = nullptr) noexcept {}
        IMidiInPortStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiMessage>
    {
        IMidiMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiMessageReceivedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiMessageReceivedEventArgs>
    {
        IMidiMessageReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IMidiMessageReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiNoteOffMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiNoteOffMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiNoteOffMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiNoteOffMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiNoteOffMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiNoteOffMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiNoteOffMessageFactory>
    {
        IMidiNoteOffMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiNoteOffMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiNoteOnMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiNoteOnMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiNoteOnMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiNoteOnMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiNoteOnMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiNoteOnMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiNoteOnMessageFactory>
    {
        IMidiNoteOnMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiNoteOnMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiOutPort :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiOutPort>,
        impl::require<winrt::Windows::Devices::Midi::IMidiOutPort, winrt::Windows::Foundation::IClosable>
    {
        IMidiOutPort(std::nullptr_t = nullptr) noexcept {}
        IMidiOutPort(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiOutPortStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiOutPortStatics>
    {
        IMidiOutPortStatics(std::nullptr_t = nullptr) noexcept {}
        IMidiOutPortStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiPitchBendChangeMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiPitchBendChangeMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiPitchBendChangeMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiPitchBendChangeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiPitchBendChangeMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiPitchBendChangeMessageFactory>
    {
        IMidiPitchBendChangeMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiPitchBendChangeMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiPolyphonicKeyPressureMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiPolyphonicKeyPressureMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiPolyphonicKeyPressureMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiPolyphonicKeyPressureMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiPolyphonicKeyPressureMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiPolyphonicKeyPressureMessageFactory>
    {
        IMidiPolyphonicKeyPressureMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiPolyphonicKeyPressureMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiProgramChangeMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiProgramChangeMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiProgramChangeMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiProgramChangeMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiProgramChangeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiProgramChangeMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiProgramChangeMessageFactory>
    {
        IMidiProgramChangeMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiProgramChangeMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiSongPositionPointerMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiSongPositionPointerMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiSongPositionPointerMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiSongPositionPointerMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiSongPositionPointerMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiSongPositionPointerMessageFactory>
    {
        IMidiSongPositionPointerMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiSongPositionPointerMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiSongSelectMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiSongSelectMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiSongSelectMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiSongSelectMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiSongSelectMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiSongSelectMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiSongSelectMessageFactory>
    {
        IMidiSongSelectMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiSongSelectMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiSynthesizer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiSynthesizer>,
        impl::require<winrt::Windows::Devices::Midi::IMidiSynthesizer, winrt::Windows::Foundation::IClosable, winrt::Windows::Devices::Midi::IMidiOutPort>
    {
        IMidiSynthesizer(std::nullptr_t = nullptr) noexcept {}
        IMidiSynthesizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiSynthesizerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiSynthesizerStatics>
    {
        IMidiSynthesizerStatics(std::nullptr_t = nullptr) noexcept {}
        IMidiSynthesizerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiSystemExclusiveMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiSystemExclusiveMessageFactory>
    {
        IMidiSystemExclusiveMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiSystemExclusiveMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiTimeCodeMessage :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiTimeCodeMessage>,
        impl::require<winrt::Windows::Devices::Midi::IMidiTimeCodeMessage, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        IMidiTimeCodeMessage(std::nullptr_t = nullptr) noexcept {}
        IMidiTimeCodeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMidiTimeCodeMessageFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMidiTimeCodeMessageFactory>
    {
        IMidiTimeCodeMessageFactory(std::nullptr_t = nullptr) noexcept {}
        IMidiTimeCodeMessageFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
