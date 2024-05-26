// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Midi_2_H
#define WINRT_Windows_Devices_Midi_2_H
#include "winrt/impl/Windows.Devices.Enumeration.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.Midi.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Midi
{
    struct __declspec(empty_bases) MidiActiveSensingMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiActiveSensingMessage(std::nullptr_t) noexcept {}
        MidiActiveSensingMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        MidiActiveSensingMessage();
    };
    struct __declspec(empty_bases) MidiChannelPressureMessage : winrt::Windows::Devices::Midi::IMidiChannelPressureMessage
    {
        MidiChannelPressureMessage(std::nullptr_t) noexcept {}
        MidiChannelPressureMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiChannelPressureMessage(ptr, take_ownership_from_abi) {}
        MidiChannelPressureMessage(uint8_t channel, uint8_t pressure);
    };
    struct __declspec(empty_bases) MidiContinueMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiContinueMessage(std::nullptr_t) noexcept {}
        MidiContinueMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        MidiContinueMessage();
    };
    struct __declspec(empty_bases) MidiControlChangeMessage : winrt::Windows::Devices::Midi::IMidiControlChangeMessage
    {
        MidiControlChangeMessage(std::nullptr_t) noexcept {}
        MidiControlChangeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiControlChangeMessage(ptr, take_ownership_from_abi) {}
        MidiControlChangeMessage(uint8_t channel, uint8_t controller, uint8_t controlValue);
    };
    struct __declspec(empty_bases) MidiInPort : winrt::Windows::Devices::Midi::IMidiInPort
    {
        MidiInPort(std::nullptr_t) noexcept {}
        MidiInPort(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiInPort(ptr, take_ownership_from_abi) {}
        static auto FromIdAsync(param::hstring const& deviceId);
        static auto GetDeviceSelector();
    };
    struct __declspec(empty_bases) MidiMessageReceivedEventArgs : winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs
    {
        MidiMessageReceivedEventArgs(std::nullptr_t) noexcept {}
        MidiMessageReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MidiNoteOffMessage : winrt::Windows::Devices::Midi::IMidiNoteOffMessage
    {
        MidiNoteOffMessage(std::nullptr_t) noexcept {}
        MidiNoteOffMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiNoteOffMessage(ptr, take_ownership_from_abi) {}
        MidiNoteOffMessage(uint8_t channel, uint8_t note, uint8_t velocity);
    };
    struct __declspec(empty_bases) MidiNoteOnMessage : winrt::Windows::Devices::Midi::IMidiNoteOnMessage
    {
        MidiNoteOnMessage(std::nullptr_t) noexcept {}
        MidiNoteOnMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiNoteOnMessage(ptr, take_ownership_from_abi) {}
        MidiNoteOnMessage(uint8_t channel, uint8_t note, uint8_t velocity);
    };
    struct __declspec(empty_bases) MidiOutPort : winrt::Windows::Devices::Midi::IMidiOutPort
    {
        MidiOutPort(std::nullptr_t) noexcept {}
        MidiOutPort(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiOutPort(ptr, take_ownership_from_abi) {}
        static auto FromIdAsync(param::hstring const& deviceId);
        static auto GetDeviceSelector();
    };
    struct __declspec(empty_bases) MidiPitchBendChangeMessage : winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage
    {
        MidiPitchBendChangeMessage(std::nullptr_t) noexcept {}
        MidiPitchBendChangeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage(ptr, take_ownership_from_abi) {}
        MidiPitchBendChangeMessage(uint8_t channel, uint16_t bend);
    };
    struct __declspec(empty_bases) MidiPolyphonicKeyPressureMessage : winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage
    {
        MidiPolyphonicKeyPressureMessage(std::nullptr_t) noexcept {}
        MidiPolyphonicKeyPressureMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage(ptr, take_ownership_from_abi) {}
        MidiPolyphonicKeyPressureMessage(uint8_t channel, uint8_t note, uint8_t pressure);
    };
    struct __declspec(empty_bases) MidiProgramChangeMessage : winrt::Windows::Devices::Midi::IMidiProgramChangeMessage
    {
        MidiProgramChangeMessage(std::nullptr_t) noexcept {}
        MidiProgramChangeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiProgramChangeMessage(ptr, take_ownership_from_abi) {}
        MidiProgramChangeMessage(uint8_t channel, uint8_t program);
    };
    struct __declspec(empty_bases) MidiSongPositionPointerMessage : winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage
    {
        MidiSongPositionPointerMessage(std::nullptr_t) noexcept {}
        MidiSongPositionPointerMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage(ptr, take_ownership_from_abi) {}
        explicit MidiSongPositionPointerMessage(uint16_t beats);
    };
    struct __declspec(empty_bases) MidiSongSelectMessage : winrt::Windows::Devices::Midi::IMidiSongSelectMessage
    {
        MidiSongSelectMessage(std::nullptr_t) noexcept {}
        MidiSongSelectMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiSongSelectMessage(ptr, take_ownership_from_abi) {}
        explicit MidiSongSelectMessage(uint8_t song);
    };
    struct __declspec(empty_bases) MidiStartMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiStartMessage(std::nullptr_t) noexcept {}
        MidiStartMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        MidiStartMessage();
    };
    struct __declspec(empty_bases) MidiStopMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiStopMessage(std::nullptr_t) noexcept {}
        MidiStopMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        MidiStopMessage();
    };
    struct __declspec(empty_bases) MidiSynthesizer : winrt::Windows::Devices::Midi::IMidiSynthesizer
    {
        MidiSynthesizer(std::nullptr_t) noexcept {}
        MidiSynthesizer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiSynthesizer(ptr, take_ownership_from_abi) {}
        static auto CreateAsync();
        static auto CreateAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& audioDevice);
        static auto IsSynthesizer(winrt::Windows::Devices::Enumeration::DeviceInformation const& midiDevice);
    };
    struct __declspec(empty_bases) MidiSystemExclusiveMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiSystemExclusiveMessage(std::nullptr_t) noexcept {}
        MidiSystemExclusiveMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        explicit MidiSystemExclusiveMessage(winrt::Windows::Storage::Streams::IBuffer const& rawData);
    };
    struct __declspec(empty_bases) MidiSystemResetMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiSystemResetMessage(std::nullptr_t) noexcept {}
        MidiSystemResetMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        MidiSystemResetMessage();
    };
    struct __declspec(empty_bases) MidiTimeCodeMessage : winrt::Windows::Devices::Midi::IMidiTimeCodeMessage
    {
        MidiTimeCodeMessage(std::nullptr_t) noexcept {}
        MidiTimeCodeMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiTimeCodeMessage(ptr, take_ownership_from_abi) {}
        MidiTimeCodeMessage(uint8_t frameType, uint8_t values);
    };
    struct __declspec(empty_bases) MidiTimingClockMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiTimingClockMessage(std::nullptr_t) noexcept {}
        MidiTimingClockMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        MidiTimingClockMessage();
    };
    struct __declspec(empty_bases) MidiTuneRequestMessage : winrt::Windows::Devices::Midi::IMidiMessage
    {
        MidiTuneRequestMessage(std::nullptr_t) noexcept {}
        MidiTuneRequestMessage(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Midi::IMidiMessage(ptr, take_ownership_from_abi) {}
        MidiTuneRequestMessage();
    };
}
#endif
