// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_UIAutomation_Core_H
#define WINRT_Windows_UI_UIAutomation_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.UIAutomation.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.UIAutomation.2.h"
#include "winrt/impl/Windows.UI.UIAutomation.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationStatus) consume_Windows_UI_UIAutomation_Core_IAutomationRemoteOperationResult<D>::Status() const
    {
        winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_UI_UIAutomation_Core_IAutomationRemoteOperationResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_UIAutomation_Core_IAutomationRemoteOperationResult<D>::ErrorLocation() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult)->get_ErrorLocation(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_UIAutomation_Core_IAutomationRemoteOperationResult<D>::HasOperand(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& operandId) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult)->HasOperand(impl::bind_in(operandId), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_UIAutomation_Core_IAutomationRemoteOperationResult<D>::GetOperand(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& operandId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult)->GetOperand(impl::bind_in(operandId), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_UIAutomation_Core_ICoreAutomationConnectionBoundObjectProvider<D>::IsComThreadingRequired() const noexcept
    {
        bool value{};
        WINRT_VERIFY_(0, WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationConnectionBoundObjectProvider)->get_IsComThreadingRequired(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRegistrarStatics<D>::RegisterAnnotationType(winrt::guid const& guid) const
    {
        winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRegistrarStatics)->RegisterAnnotationType(impl::bind_in(guid), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRegistrarStatics<D>::UnregisterAnnotationType(winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration const& registration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRegistrarStatics)->UnregisterAnnotationType(impl::bind_in(registration)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperation<D>::IsOpcodeSupported(uint32_t opcode) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation)->IsOpcodeSupported(opcode, &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperation<D>::ImportElement(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& operandId, winrt::Windows::UI::UIAutomation::AutomationElement const& element) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation)->ImportElement(impl::bind_in(operandId), *(void**)(&element)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperation<D>::ImportTextRange(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& operandId, winrt::Windows::UI::UIAutomation::AutomationTextRange const& textRange) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation)->ImportTextRange(impl::bind_in(operandId), *(void**)(&textRange)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperation<D>::AddToResults(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& operandId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation)->AddToResults(impl::bind_in(operandId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationResult) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperation<D>::Execute(array_view<uint8_t const> bytecodeBuffer) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation)->Execute(bytecodeBuffer.size(), get_abi(bytecodeBuffer), &result));
        return winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperation2<D>::ImportConnectionBoundObject(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& operandId, winrt::Windows::UI::UIAutomation::AutomationConnectionBoundObject const& connectionBoundObject) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation2)->ImportConnectionBoundObject(impl::bind_in(operandId), *(void**)(&connectionBoundObject)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperationContext<D>::GetOperand(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext)->GetOperand(impl::bind_in(id), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperationContext<D>::SetOperand(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& id, winrt::Windows::Foundation::IInspectable const& operand) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext)->SetOperand(impl::bind_in(id), *(void**)(&operand)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperationContext<D>::SetOperand(winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const& id, winrt::Windows::Foundation::IInspectable const& operand, winrt::guid const& operandInterfaceId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext)->SetOperand2(impl::bind_in(id), *(void**)(&operand), impl::bind_in(operandInterfaceId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperationExtensionProvider<D>::CallExtension(winrt::guid const& extensionId, winrt::Windows::UI::UIAutomation::Core::CoreAutomationRemoteOperationContext const& context, array_view<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const> operandIds) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationExtensionProvider)->CallExtension(impl::bind_in(extensionId), *(void**)(&context), operandIds.size(), get_abi(operandIds)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_UIAutomation_Core_ICoreAutomationRemoteOperationExtensionProvider<D>::IsExtensionSupported(winrt::guid const& extensionId) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationExtensionProvider)->IsExtensionSupported(impl::bind_in(extensionId), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationWindow>) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::CreateWindowAsync(uint64_t remoteWindowId, uint32_t remoteProcessId, winrt::Windows::Foundation::IInspectable const& parentAutomationElement) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->CreateWindowAsync(remoteWindowId, remoteProcessId, *(void**)(&parentAutomationElement), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationWindow>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::guid) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::SessionId() const
    {
        winrt::guid value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->get_SessionId(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::ConnectionRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession, winrt::Windows::UI::UIAutomation::Core::RemoteAutomationConnectionRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->add_ConnectionRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::ConnectionRequested_revoker consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::ConnectionRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession, winrt::Windows::UI::UIAutomation::Core::RemoteAutomationConnectionRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, ConnectionRequested_revoker>(this, ConnectionRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::ConnectionRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->remove_ConnectionRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::Disconnected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession, winrt::Windows::UI::UIAutomation::Core::RemoteAutomationDisconnectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->add_Disconnected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::Disconnected_revoker consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::Disconnected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession, winrt::Windows::UI::UIAutomation::Core::RemoteAutomationDisconnectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Disconnected_revoker>(this, Disconnected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSession<D>::Disconnected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession)->remove_Disconnected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSessionFactory<D>::CreateInstance(param::hstring const& name) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSessionFactory)->CreateInstance(*(void**)(&name), &value));
        return winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationClientSessionFactory<D>::CreateInstance2(param::hstring const& name, winrt::guid const& sessionId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSessionFactory)->CreateInstance2(*(void**)(&name), impl::bind_in(sessionId), &value));
        return winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationConnectionRequestedEventArgs<D>::LocalPipeName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationConnectionRequestedEventArgs)->get_LocalPipeName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationConnectionRequestedEventArgs<D>::RemoteProcessId() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationConnectionRequestedEventArgs)->get_RemoteProcessId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationDisconnectedEventArgs<D>::LocalPipeName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationDisconnectedEventArgs)->get_LocalPipeName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationServerStatics<D>::ReportSession(winrt::guid const& sessionId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationServerStatics)->ReportSession(impl::bind_in(sessionId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationWindow<D>::AutomationProvider() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationWindow)->get_AutomationProvider(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_UIAutomation_Core_IRemoteAutomationWindow<D>::UnregisterAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationWindow)->UnregisterAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ErrorLocation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ErrorLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall HasOperand(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId operandId, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().HasOperand(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&operandId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOperand(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId operandId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetOperand(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&operandId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationConnectionBoundObjectProvider> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationConnectionBoundObjectProvider>
    {
        int32_t __stdcall get_IsComThreadingRequired(bool* value) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsComThreadingRequired());
            return 0;
        }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRegistrarStatics> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRegistrarStatics>
    {
        int32_t __stdcall RegisterAnnotationType(winrt::guid guid, struct struct_Windows_UI_UIAutomation_Core_AutomationAnnotationTypeRegistration* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration>(this->shim().RegisterAnnotationType(*reinterpret_cast<winrt::guid const*>(&guid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterAnnotationType(struct struct_Windows_UI_UIAutomation_Core_AutomationAnnotationTypeRegistration registration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnregisterAnnotationType(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration const*>(&registration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation>
    {
        int32_t __stdcall IsOpcodeSupported(uint32_t opcode, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsOpcodeSupported(opcode));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ImportElement(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId operandId, void* element) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImportElement(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&operandId), *reinterpret_cast<winrt::Windows::UI::UIAutomation::AutomationElement const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ImportTextRange(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId operandId, void* textRange) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImportTextRange(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&operandId), *reinterpret_cast<winrt::Windows::UI::UIAutomation::AutomationTextRange const*>(&textRange));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToResults(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId operandId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToResults(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&operandId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Execute(uint32_t __bytecodeBufferSize, uint8_t* bytecodeBuffer, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationResult>(this->shim().Execute(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(bytecodeBuffer), reinterpret_cast<uint8_t const *>(bytecodeBuffer) + __bytecodeBufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation2> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation2>
    {
        int32_t __stdcall ImportConnectionBoundObject(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId operandId, void* connectionBoundObject) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImportConnectionBoundObject(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&operandId), *reinterpret_cast<winrt::Windows::UI::UIAutomation::AutomationConnectionBoundObject const*>(&connectionBoundObject));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext>
    {
        int32_t __stdcall GetOperand(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetOperand(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetOperand(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId id, void* operand) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetOperand(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&id), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&operand));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetOperand2(struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId id, void* operand, winrt::guid operandInterfaceId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetOperand(*reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const*>(&id), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&operand), *reinterpret_cast<winrt::guid const*>(&operandInterfaceId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationExtensionProvider> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationExtensionProvider>
    {
        int32_t __stdcall CallExtension(winrt::guid extensionId, void* context, uint32_t __operandIdsSize, struct struct_Windows_UI_UIAutomation_Core_AutomationRemoteOperationOperandId* operandIds) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CallExtension(*reinterpret_cast<winrt::guid const*>(&extensionId), *reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::CoreAutomationRemoteOperationContext const*>(&context), array_view<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const>(reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const *>(operandIds), reinterpret_cast<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationOperandId const *>(operandIds) + __operandIdsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsExtensionSupported(winrt::guid extensionId, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsExtensionSupported(*reinterpret_cast<winrt::guid const*>(&extensionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession>
    {
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWindowAsync(uint64_t remoteWindowId, uint32_t remoteProcessId, void* parentAutomationElement, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationWindow>>(this->shim().CreateWindowAsync(remoteWindowId, remoteProcessId, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&parentAutomationElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionId(winrt::guid* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::guid>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ConnectionRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConnectionRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession, winrt::Windows::UI::UIAutomation::Core::RemoteAutomationConnectionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConnectionRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConnectionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Disconnected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Disconnected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession, winrt::Windows::UI::UIAutomation::Core::RemoteAutomationDisconnectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Disconnected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disconnected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSessionFactory> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSessionFactory>
    {
        int32_t __stdcall CreateInstance(void* name, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstance2(void* name, winrt::guid sessionId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession>(this->shim().CreateInstance2(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<winrt::guid const*>(&sessionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationConnectionRequestedEventArgs> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationConnectionRequestedEventArgs>
    {
        int32_t __stdcall get_LocalPipeName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalPipeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoteProcessId(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().RemoteProcessId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationDisconnectedEventArgs> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationDisconnectedEventArgs>
    {
        int32_t __stdcall get_LocalPipeName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalPipeName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationServerStatics> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationServerStatics>
    {
        int32_t __stdcall ReportSession(winrt::guid sessionId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportSession(*reinterpret_cast<winrt::guid const*>(&sessionId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationWindow> : produce_base<D, winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationWindow>
    {
        int32_t __stdcall get_AutomationProvider(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().AutomationProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UnregisterAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().UnregisterAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::UIAutomation::Core
{
    inline auto CoreAutomationRegistrar::RegisterAnnotationType(winrt::guid const& guid)
    {
        return impl::call_factory<CoreAutomationRegistrar, ICoreAutomationRegistrarStatics>([&](ICoreAutomationRegistrarStatics const& f) { return f.RegisterAnnotationType(guid); });
    }
    inline auto CoreAutomationRegistrar::UnregisterAnnotationType(winrt::Windows::UI::UIAutomation::Core::AutomationAnnotationTypeRegistration const& registration)
    {
        impl::call_factory<CoreAutomationRegistrar, ICoreAutomationRegistrarStatics>([&](ICoreAutomationRegistrarStatics const& f) { return f.UnregisterAnnotationType(registration); });
    }
    inline CoreAutomationRemoteOperation::CoreAutomationRemoteOperation() :
        CoreAutomationRemoteOperation(impl::call_factory_cast<CoreAutomationRemoteOperation(*)(winrt::Windows::Foundation::IActivationFactory const&), CoreAutomationRemoteOperation>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CoreAutomationRemoteOperation>(); }))
    {
    }
    inline RemoteAutomationClientSession::RemoteAutomationClientSession(param::hstring const& name) :
        RemoteAutomationClientSession(impl::call_factory<RemoteAutomationClientSession, IRemoteAutomationClientSessionFactory>([&](IRemoteAutomationClientSessionFactory const& f) { return f.CreateInstance(name); }))
    {
    }
    inline RemoteAutomationClientSession::RemoteAutomationClientSession(param::hstring const& name, winrt::guid const& sessionId) :
        RemoteAutomationClientSession(impl::call_factory<RemoteAutomationClientSession, IRemoteAutomationClientSessionFactory>([&](IRemoteAutomationClientSessionFactory const& f) { return f.CreateInstance2(name, sessionId); }))
    {
    }
    inline auto RemoteAutomationServer::ReportSession(winrt::guid const& sessionId)
    {
        impl::call_factory<RemoteAutomationServer, IRemoteAutomationServerStatics>([&](IRemoteAutomationServerStatics const& f) { return f.ReportSession(sessionId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::IAutomationRemoteOperationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::ICoreAutomationConnectionBoundObjectProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRegistrarStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperation2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::ICoreAutomationRemoteOperationExtensionProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationClientSessionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationConnectionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationDisconnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationServerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::IRemoteAutomationWindow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::AutomationRemoteOperationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::CoreAutomationRegistrar> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::CoreAutomationRemoteOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::CoreAutomationRemoteOperationContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationClientSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationConnectionRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationDisconnectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationServer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::UIAutomation::Core::RemoteAutomationWindow> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
