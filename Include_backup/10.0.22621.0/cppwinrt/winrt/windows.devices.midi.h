// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Midi_H
#define WINRT_Windows_Devices_Midi_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Midi.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiChannelPressureMessage<D>::Channel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiChannelPressureMessage)->get_Channel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiChannelPressureMessage<D>::Pressure() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiChannelPressureMessage)->get_Pressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiChannelPressureMessage) consume_Windows_Devices_Midi_IMidiChannelPressureMessageFactory<D>::CreateMidiChannelPressureMessage(uint8_t channel, uint8_t pressure) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiChannelPressureMessageFactory)->CreateMidiChannelPressureMessage(channel, pressure, &value));
        return winrt::Windows::Devices::Midi::MidiChannelPressureMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiControlChangeMessage<D>::Channel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiControlChangeMessage)->get_Channel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiControlChangeMessage<D>::Controller() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiControlChangeMessage)->get_Controller(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiControlChangeMessage<D>::ControlValue() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiControlChangeMessage)->get_ControlValue(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiControlChangeMessage) consume_Windows_Devices_Midi_IMidiControlChangeMessageFactory<D>::CreateMidiControlChangeMessage(uint8_t channel, uint8_t controller, uint8_t controlValue) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiControlChangeMessageFactory)->CreateMidiControlChangeMessage(channel, controller, controlValue, &value));
        return winrt::Windows::Devices::Midi::MidiControlChangeMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Midi::MidiInPort, winrt::Windows::Devices::Midi::MidiMessageReceivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiInPort)->add_MessageReceived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived_revoker consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Midi::MidiInPort, winrt::Windows::Devices::Midi::MidiMessageReceivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Midi_IMidiInPort<D>::MessageReceived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiInPort)->remove_MessageReceived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Midi_IMidiInPort<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiInPort)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiInPort>) consume_Windows_Devices_Midi_IMidiInPortStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiInPortStatics)->FromIdAsync(*(void**)(&deviceId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiInPort>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Midi_IMidiInPortStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiInPortStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Midi_IMidiMessage<D>::Timestamp() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiMessage)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Devices_Midi_IMidiMessage<D>::RawData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiMessage)->get_RawData(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiMessageType) consume_Windows_Devices_Midi_IMidiMessage<D>::Type() const
    {
        winrt::Windows::Devices::Midi::MidiMessageType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiMessage)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::IMidiMessage) consume_Windows_Devices_Midi_IMidiMessageReceivedEventArgs<D>::Message() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs)->get_Message(&value));
        return winrt::Windows::Devices::Midi::IMidiMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiNoteOffMessage<D>::Channel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOffMessage)->get_Channel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiNoteOffMessage<D>::Note() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOffMessage)->get_Note(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiNoteOffMessage<D>::Velocity() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOffMessage)->get_Velocity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiNoteOffMessage) consume_Windows_Devices_Midi_IMidiNoteOffMessageFactory<D>::CreateMidiNoteOffMessage(uint8_t channel, uint8_t note, uint8_t velocity) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOffMessageFactory)->CreateMidiNoteOffMessage(channel, note, velocity, &value));
        return winrt::Windows::Devices::Midi::MidiNoteOffMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiNoteOnMessage<D>::Channel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOnMessage)->get_Channel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiNoteOnMessage<D>::Note() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOnMessage)->get_Note(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiNoteOnMessage<D>::Velocity() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOnMessage)->get_Velocity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiNoteOnMessage) consume_Windows_Devices_Midi_IMidiNoteOnMessageFactory<D>::CreateMidiNoteOnMessage(uint8_t channel, uint8_t note, uint8_t velocity) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiNoteOnMessageFactory)->CreateMidiNoteOnMessage(channel, note, velocity, &value));
        return winrt::Windows::Devices::Midi::MidiNoteOnMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Midi_IMidiOutPort<D>::SendMessage(winrt::Windows::Devices::Midi::IMidiMessage const& midiMessage) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiOutPort)->SendMessage(*(void**)(&midiMessage)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Midi_IMidiOutPort<D>::SendBuffer(winrt::Windows::Storage::Streams::IBuffer const& midiData) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiOutPort)->SendBuffer(*(void**)(&midiData)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Midi_IMidiOutPort<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiOutPort)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::IMidiOutPort>) consume_Windows_Devices_Midi_IMidiOutPortStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiOutPortStatics)->FromIdAsync(*(void**)(&deviceId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::IMidiOutPort>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Midi_IMidiOutPortStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiOutPortStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiPitchBendChangeMessage<D>::Channel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage)->get_Channel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Midi_IMidiPitchBendChangeMessage<D>::Bend() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage)->get_Bend(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiPitchBendChangeMessage) consume_Windows_Devices_Midi_IMidiPitchBendChangeMessageFactory<D>::CreateMidiPitchBendChangeMessage(uint8_t channel, uint16_t bend) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory)->CreateMidiPitchBendChangeMessage(channel, bend, &value));
        return winrt::Windows::Devices::Midi::MidiPitchBendChangeMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessage<D>::Channel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage)->get_Channel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessage<D>::Note() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage)->get_Note(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessage<D>::Pressure() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage)->get_Pressure(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage) consume_Windows_Devices_Midi_IMidiPolyphonicKeyPressureMessageFactory<D>::CreateMidiPolyphonicKeyPressureMessage(uint8_t channel, uint8_t note, uint8_t pressure) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory)->CreateMidiPolyphonicKeyPressureMessage(channel, note, pressure, &value));
        return winrt::Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiProgramChangeMessage<D>::Channel() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiProgramChangeMessage)->get_Channel(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiProgramChangeMessage<D>::Program() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiProgramChangeMessage)->get_Program(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiProgramChangeMessage) consume_Windows_Devices_Midi_IMidiProgramChangeMessageFactory<D>::CreateMidiProgramChangeMessage(uint8_t channel, uint8_t program) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiProgramChangeMessageFactory)->CreateMidiProgramChangeMessage(channel, program, &value));
        return winrt::Windows::Devices::Midi::MidiProgramChangeMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Midi_IMidiSongPositionPointerMessage<D>::Beats() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage)->get_Beats(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiSongPositionPointerMessage) consume_Windows_Devices_Midi_IMidiSongPositionPointerMessageFactory<D>::CreateMidiSongPositionPointerMessage(uint16_t beats) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory)->CreateMidiSongPositionPointerMessage(beats, &value));
        return winrt::Windows::Devices::Midi::MidiSongPositionPointerMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiSongSelectMessage<D>::Song() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSongSelectMessage)->get_Song(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiSongSelectMessage) consume_Windows_Devices_Midi_IMidiSongSelectMessageFactory<D>::CreateMidiSongSelectMessage(uint8_t song) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSongSelectMessageFactory)->CreateMidiSongSelectMessage(song, &value));
        return winrt::Windows::Devices::Midi::MidiSongSelectMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Devices_Midi_IMidiSynthesizer<D>::AudioDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSynthesizer)->get_AudioDevice(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Devices_Midi_IMidiSynthesizer<D>::Volume() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSynthesizer)->get_Volume(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Midi_IMidiSynthesizer<D>::Volume(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSynthesizer)->put_Volume(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiSynthesizer>) consume_Windows_Devices_Midi_IMidiSynthesizerStatics<D>::CreateAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSynthesizerStatics)->CreateAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiSynthesizer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiSynthesizer>) consume_Windows_Devices_Midi_IMidiSynthesizerStatics<D>::CreateAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& audioDevice) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSynthesizerStatics)->CreateFromAudioDeviceAsync(*(void**)(&audioDevice), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiSynthesizer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Midi_IMidiSynthesizerStatics<D>::IsSynthesizer(winrt::Windows::Devices::Enumeration::DeviceInformation const& midiDevice) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSynthesizerStatics)->IsSynthesizer(*(void**)(&midiDevice), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiSystemExclusiveMessage) consume_Windows_Devices_Midi_IMidiSystemExclusiveMessageFactory<D>::CreateMidiSystemExclusiveMessage(winrt::Windows::Storage::Streams::IBuffer const& rawData) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory)->CreateMidiSystemExclusiveMessage(*(void**)(&rawData), &value));
        return winrt::Windows::Devices::Midi::MidiSystemExclusiveMessage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiTimeCodeMessage<D>::FrameType() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiTimeCodeMessage)->get_FrameType(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Devices_Midi_IMidiTimeCodeMessage<D>::Values() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiTimeCodeMessage)->get_Values(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Midi::MidiTimeCodeMessage) consume_Windows_Devices_Midi_IMidiTimeCodeMessageFactory<D>::CreateMidiTimeCodeMessage(uint8_t frameType, uint8_t values) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Midi::IMidiTimeCodeMessageFactory)->CreateMidiTimeCodeMessage(frameType, values, &value));
        return winrt::Windows::Devices::Midi::MidiTimeCodeMessage{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiChannelPressureMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiChannelPressureMessage>
    {
        int32_t __stdcall get_Channel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pressure(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiChannelPressureMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiChannelPressureMessageFactory>
    {
        int32_t __stdcall CreateMidiChannelPressureMessage(uint8_t channel, uint8_t pressure, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiChannelPressureMessage>(this->shim().CreateMidiChannelPressureMessage(channel, pressure));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiControlChangeMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiControlChangeMessage>
    {
        int32_t __stdcall get_Channel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Controller(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ControlValue(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ControlValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiControlChangeMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiControlChangeMessageFactory>
    {
        int32_t __stdcall CreateMidiControlChangeMessage(uint8_t channel, uint8_t controller, uint8_t controlValue, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiControlChangeMessage>(this->shim().CreateMidiControlChangeMessage(channel, controller, controlValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiInPort> : produce_base<D, winrt::Windows::Devices::Midi::IMidiInPort>
    {
        int32_t __stdcall add_MessageReceived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Midi::MidiInPort, winrt::Windows::Devices::Midi::MidiMessageReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MessageReceived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiInPortStatics> : produce_base<D, winrt::Windows::Devices::Midi::IMidiInPortStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiInPort>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiMessage>
    {
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RawData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().RawData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiMessageType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs> : produce_base<D, winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs>
    {
        int32_t __stdcall get_Message(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::IMidiMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiNoteOffMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiNoteOffMessage>
    {
        int32_t __stdcall get_Channel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Note(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Note());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Velocity(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Velocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiNoteOffMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiNoteOffMessageFactory>
    {
        int32_t __stdcall CreateMidiNoteOffMessage(uint8_t channel, uint8_t note, uint8_t velocity, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiNoteOffMessage>(this->shim().CreateMidiNoteOffMessage(channel, note, velocity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiNoteOnMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiNoteOnMessage>
    {
        int32_t __stdcall get_Channel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Note(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Note());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Velocity(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Velocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiNoteOnMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiNoteOnMessageFactory>
    {
        int32_t __stdcall CreateMidiNoteOnMessage(uint8_t channel, uint8_t note, uint8_t velocity, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiNoteOnMessage>(this->shim().CreateMidiNoteOnMessage(channel, note, velocity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiOutPort> : produce_base<D, winrt::Windows::Devices::Midi::IMidiOutPort>
    {
        int32_t __stdcall SendMessage(void* midiMessage) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendMessage(*reinterpret_cast<winrt::Windows::Devices::Midi::IMidiMessage const*>(&midiMessage));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendBuffer(void* midiData) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&midiData));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiOutPortStatics> : produce_base<D, winrt::Windows::Devices::Midi::IMidiOutPortStatics>
    {
        int32_t __stdcall FromIdAsync(void* deviceId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::IMidiOutPort>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage>
    {
        int32_t __stdcall get_Channel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bend(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Bend());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory>
    {
        int32_t __stdcall CreateMidiPitchBendChangeMessage(uint8_t channel, uint16_t bend, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiPitchBendChangeMessage>(this->shim().CreateMidiPitchBendChangeMessage(channel, bend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage>
    {
        int32_t __stdcall get_Channel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Note(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Note());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pressure(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory>
    {
        int32_t __stdcall CreateMidiPolyphonicKeyPressureMessage(uint8_t channel, uint8_t note, uint8_t pressure, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage>(this->shim().CreateMidiPolyphonicKeyPressureMessage(channel, note, pressure));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiProgramChangeMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiProgramChangeMessage>
    {
        int32_t __stdcall get_Channel(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Channel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Program(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Program());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiProgramChangeMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiProgramChangeMessageFactory>
    {
        int32_t __stdcall CreateMidiProgramChangeMessage(uint8_t channel, uint8_t program, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiProgramChangeMessage>(this->shim().CreateMidiProgramChangeMessage(channel, program));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage>
    {
        int32_t __stdcall get_Beats(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Beats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory>
    {
        int32_t __stdcall CreateMidiSongPositionPointerMessage(uint16_t beats, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiSongPositionPointerMessage>(this->shim().CreateMidiSongPositionPointerMessage(beats));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiSongSelectMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiSongSelectMessage>
    {
        int32_t __stdcall get_Song(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Song());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiSongSelectMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiSongSelectMessageFactory>
    {
        int32_t __stdcall CreateMidiSongSelectMessage(uint8_t song, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiSongSelectMessage>(this->shim().CreateMidiSongSelectMessage(song));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiSynthesizer> : produce_base<D, winrt::Windows::Devices::Midi::IMidiSynthesizer>
    {
        int32_t __stdcall get_AudioDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().AudioDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Volume(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Volume());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Volume(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Volume(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiSynthesizerStatics> : produce_base<D, winrt::Windows::Devices::Midi::IMidiSynthesizerStatics>
    {
        int32_t __stdcall CreateAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiSynthesizer>>(this->shim().CreateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromAudioDeviceAsync(void* audioDevice, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiSynthesizer>>(this->shim().CreateAsync(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&audioDevice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSynthesizer(void* midiDevice, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSynthesizer(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&midiDevice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory>
    {
        int32_t __stdcall CreateMidiSystemExclusiveMessage(void* rawData, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiSystemExclusiveMessage>(this->shim().CreateMidiSystemExclusiveMessage(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&rawData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiTimeCodeMessage> : produce_base<D, winrt::Windows::Devices::Midi::IMidiTimeCodeMessage>
    {
        int32_t __stdcall get_FrameType(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().FrameType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Values(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().Values());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Midi::IMidiTimeCodeMessageFactory> : produce_base<D, winrt::Windows::Devices::Midi::IMidiTimeCodeMessageFactory>
    {
        int32_t __stdcall CreateMidiTimeCodeMessage(uint8_t frameType, uint8_t values, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Midi::MidiTimeCodeMessage>(this->shim().CreateMidiTimeCodeMessage(frameType, values));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Midi
{
    inline MidiActiveSensingMessage::MidiActiveSensingMessage() :
        MidiActiveSensingMessage(impl::call_factory_cast<MidiActiveSensingMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), MidiActiveSensingMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MidiActiveSensingMessage>(); }))
    {
    }
    inline MidiChannelPressureMessage::MidiChannelPressureMessage(uint8_t channel, uint8_t pressure) :
        MidiChannelPressureMessage(impl::call_factory<MidiChannelPressureMessage, IMidiChannelPressureMessageFactory>([&](IMidiChannelPressureMessageFactory const& f) { return f.CreateMidiChannelPressureMessage(channel, pressure); }))
    {
    }
    inline MidiContinueMessage::MidiContinueMessage() :
        MidiContinueMessage(impl::call_factory_cast<MidiContinueMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), MidiContinueMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MidiContinueMessage>(); }))
    {
    }
    inline MidiControlChangeMessage::MidiControlChangeMessage(uint8_t channel, uint8_t controller, uint8_t controlValue) :
        MidiControlChangeMessage(impl::call_factory<MidiControlChangeMessage, IMidiControlChangeMessageFactory>([&](IMidiControlChangeMessageFactory const& f) { return f.CreateMidiControlChangeMessage(channel, controller, controlValue); }))
    {
    }
    inline auto MidiInPort::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<MidiInPort, IMidiInPortStatics>([&](IMidiInPortStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto MidiInPort::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IMidiInPortStatics const&), MidiInPort, IMidiInPortStatics>([](IMidiInPortStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline MidiNoteOffMessage::MidiNoteOffMessage(uint8_t channel, uint8_t note, uint8_t velocity) :
        MidiNoteOffMessage(impl::call_factory<MidiNoteOffMessage, IMidiNoteOffMessageFactory>([&](IMidiNoteOffMessageFactory const& f) { return f.CreateMidiNoteOffMessage(channel, note, velocity); }))
    {
    }
    inline MidiNoteOnMessage::MidiNoteOnMessage(uint8_t channel, uint8_t note, uint8_t velocity) :
        MidiNoteOnMessage(impl::call_factory<MidiNoteOnMessage, IMidiNoteOnMessageFactory>([&](IMidiNoteOnMessageFactory const& f) { return f.CreateMidiNoteOnMessage(channel, note, velocity); }))
    {
    }
    inline auto MidiOutPort::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<MidiOutPort, IMidiOutPortStatics>([&](IMidiOutPortStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto MidiOutPort::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IMidiOutPortStatics const&), MidiOutPort, IMidiOutPortStatics>([](IMidiOutPortStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline MidiPitchBendChangeMessage::MidiPitchBendChangeMessage(uint8_t channel, uint16_t bend) :
        MidiPitchBendChangeMessage(impl::call_factory<MidiPitchBendChangeMessage, IMidiPitchBendChangeMessageFactory>([&](IMidiPitchBendChangeMessageFactory const& f) { return f.CreateMidiPitchBendChangeMessage(channel, bend); }))
    {
    }
    inline MidiPolyphonicKeyPressureMessage::MidiPolyphonicKeyPressureMessage(uint8_t channel, uint8_t note, uint8_t pressure) :
        MidiPolyphonicKeyPressureMessage(impl::call_factory<MidiPolyphonicKeyPressureMessage, IMidiPolyphonicKeyPressureMessageFactory>([&](IMidiPolyphonicKeyPressureMessageFactory const& f) { return f.CreateMidiPolyphonicKeyPressureMessage(channel, note, pressure); }))
    {
    }
    inline MidiProgramChangeMessage::MidiProgramChangeMessage(uint8_t channel, uint8_t program) :
        MidiProgramChangeMessage(impl::call_factory<MidiProgramChangeMessage, IMidiProgramChangeMessageFactory>([&](IMidiProgramChangeMessageFactory const& f) { return f.CreateMidiProgramChangeMessage(channel, program); }))
    {
    }
    inline MidiSongPositionPointerMessage::MidiSongPositionPointerMessage(uint16_t beats) :
        MidiSongPositionPointerMessage(impl::call_factory<MidiSongPositionPointerMessage, IMidiSongPositionPointerMessageFactory>([&](IMidiSongPositionPointerMessageFactory const& f) { return f.CreateMidiSongPositionPointerMessage(beats); }))
    {
    }
    inline MidiSongSelectMessage::MidiSongSelectMessage(uint8_t song) :
        MidiSongSelectMessage(impl::call_factory<MidiSongSelectMessage, IMidiSongSelectMessageFactory>([&](IMidiSongSelectMessageFactory const& f) { return f.CreateMidiSongSelectMessage(song); }))
    {
    }
    inline MidiStartMessage::MidiStartMessage() :
        MidiStartMessage(impl::call_factory_cast<MidiStartMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), MidiStartMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MidiStartMessage>(); }))
    {
    }
    inline MidiStopMessage::MidiStopMessage() :
        MidiStopMessage(impl::call_factory_cast<MidiStopMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), MidiStopMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MidiStopMessage>(); }))
    {
    }
    inline auto MidiSynthesizer::CreateAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Midi::MidiSynthesizer>(*)(IMidiSynthesizerStatics const&), MidiSynthesizer, IMidiSynthesizerStatics>([](IMidiSynthesizerStatics const& f) { return f.CreateAsync(); });
    }
    inline auto MidiSynthesizer::CreateAsync(winrt::Windows::Devices::Enumeration::DeviceInformation const& audioDevice)
    {
        return impl::call_factory<MidiSynthesizer, IMidiSynthesizerStatics>([&](IMidiSynthesizerStatics const& f) { return f.CreateAsync(audioDevice); });
    }
    inline auto MidiSynthesizer::IsSynthesizer(winrt::Windows::Devices::Enumeration::DeviceInformation const& midiDevice)
    {
        return impl::call_factory<MidiSynthesizer, IMidiSynthesizerStatics>([&](IMidiSynthesizerStatics const& f) { return f.IsSynthesizer(midiDevice); });
    }
    inline MidiSystemExclusiveMessage::MidiSystemExclusiveMessage(winrt::Windows::Storage::Streams::IBuffer const& rawData) :
        MidiSystemExclusiveMessage(impl::call_factory<MidiSystemExclusiveMessage, IMidiSystemExclusiveMessageFactory>([&](IMidiSystemExclusiveMessageFactory const& f) { return f.CreateMidiSystemExclusiveMessage(rawData); }))
    {
    }
    inline MidiSystemResetMessage::MidiSystemResetMessage() :
        MidiSystemResetMessage(impl::call_factory_cast<MidiSystemResetMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), MidiSystemResetMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MidiSystemResetMessage>(); }))
    {
    }
    inline MidiTimeCodeMessage::MidiTimeCodeMessage(uint8_t frameType, uint8_t values) :
        MidiTimeCodeMessage(impl::call_factory<MidiTimeCodeMessage, IMidiTimeCodeMessageFactory>([&](IMidiTimeCodeMessageFactory const& f) { return f.CreateMidiTimeCodeMessage(frameType, values); }))
    {
    }
    inline MidiTimingClockMessage::MidiTimingClockMessage() :
        MidiTimingClockMessage(impl::call_factory_cast<MidiTimingClockMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), MidiTimingClockMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MidiTimingClockMessage>(); }))
    {
    }
    inline MidiTuneRequestMessage::MidiTuneRequestMessage() :
        MidiTuneRequestMessage(impl::call_factory_cast<MidiTuneRequestMessage(*)(winrt::Windows::Foundation::IActivationFactory const&), MidiTuneRequestMessage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MidiTuneRequestMessage>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiChannelPressureMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiChannelPressureMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiControlChangeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiControlChangeMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiInPort> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiInPortStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiMessageReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOffMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOffMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOnMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiNoteOnMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiOutPort> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiOutPortStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiPitchBendChangeMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiPolyphonicKeyPressureMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiProgramChangeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiProgramChangeMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongPositionPointerMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongSelectMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiSongSelectMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiSynthesizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiSynthesizerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiSystemExclusiveMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiTimeCodeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::IMidiTimeCodeMessageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiActiveSensingMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiChannelPressureMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiContinueMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiControlChangeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiInPort> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiMessageReceivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiNoteOffMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiNoteOnMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiOutPort> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiPitchBendChangeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiPolyphonicKeyPressureMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiProgramChangeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiSongPositionPointerMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiSongSelectMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiStartMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiStopMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiSynthesizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiSystemExclusiveMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiSystemResetMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiTimeCodeMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiTimingClockMessage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Midi::MidiTuneRequestMessage> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
